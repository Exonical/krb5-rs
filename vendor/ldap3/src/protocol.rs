use std::io;
use std::sync::RwLock;
use std::sync::{Arc, Mutex};

use crate::RequestId;
use crate::controls::{Control, RawControl};
use crate::controls_impl::{build_tag, parse_controls};
use crate::search::SearchItem;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Integer, Sequence, Tag};
use lber::universal::Types;
use lber::write;

use bytes::{Buf, BytesMut};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct LdapCodec {
    pub(crate) has_decoded_data: bool,
    pub(crate) sasl_param: Arc<RwLock<(bool, u32)>>, // sasl_wrap, sasl_max_send
    pub(crate) client_ctx: Arc<Mutex<Option<Box<dyn crate::SaslSecurityLayer>>>>,
}

pub(crate) type MaybeControls = Option<Vec<RawControl>>;
pub(crate) type ItemSender = mpsc::UnboundedSender<(SearchItem, Vec<Control>)>;
pub(crate) type ResultSender = oneshot::Sender<(Tag, Vec<Control>)>;

#[derive(Debug)]
pub enum MiscSender {
    #[cfg(any(any(), feature = "tls-rustls"))]
    Cert(oneshot::Sender<Option<Vec<u8>>>),
}

#[derive(Debug)]
pub enum LdapOp {
    Single,
    Search(ItemSender),
    Abandon(RequestId),
    Unbind,
}

#[allow(clippy::type_complexity)]
fn decode_inner(buf: &mut BytesMut) -> Result<Option<(RequestId, (Tag, Vec<Control>))>, io::Error> {
    let decoding_error = io::Error::new(io::ErrorKind::Other, "decoding error");
    let mut parser = lber::Parser::new();
    let binding = parser.parse(buf);
    let (i, tag) = match binding {
        Err(e) if e.is_incomplete() => return Ok(None),
        Err(_e) => return Err(decoding_error),
        Ok((i, ref tag)) => (i, tag),
    };
    buf.advance(buf.len() - i.len());
    let tag = tag.clone();
    let mut tags = match tag
        .match_id(Types::Sequence as u64)
        .and_then(|t| t.expect_constructed())
    {
        Some(tags) => tags,
        None => return Err(decoding_error),
    };
    let mut maybe_controls = tags.pop().expect("element");
    let has_controls = match maybe_controls {
        StructureTag {
            id,
            class,
            ref payload,
        } if class == TagClass::Context && id == 0 => match *payload {
            PL::C(_) => true,
            PL::P(_) => return Err(decoding_error),
        },
        StructureTag { id, class, .. } if class == TagClass::Context && id == 10 => {
            // Active Directory bug workaround
            //
            // AD incorrectly encodes Notice of Disconnection messages. The OID of the
            // Unsolicited Notification should be part of the ExtendedResponse sequence
            // but AD puts it outside, where the optional controls belong. This confuses
            // our parser, which doesn't expect the extra sequence element at the end
            // and crashes. This match arm thus ignores the element.
            maybe_controls = tags.pop().expect("element");
            false
        }
        _ => false,
    };
    let (protoop, controls) = if has_controls {
        (tags.pop().expect("element"), Some(maybe_controls))
    } else {
        (maybe_controls, None)
    };
    let controls = match controls {
        Some(controls) => parse_controls(controls),
        None => vec![],
    };
    let msgid = match parse_uint(
        tags.pop()
            .expect("element")
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .expect("message id")
            .as_slice(),
    ) {
        Ok((_, id)) => id as i32,
        _ => return Err(decoding_error),
    };
    Ok(Some((msgid, (Tag::StructureTag(protoop), controls))))
}

impl Decoder for LdapCodec {
    type Item = (RequestId, (Tag, Vec<Control>));
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();

        let sasl_wrap = { self.sasl_param.read().expect("sasl param").0 };
        if !sasl_wrap || buf.is_empty() {
            return decode_inner(buf);
        }
        if self.has_decoded_data {
            let res = decode_inner(buf);
            if res.is_ok() && buf.is_empty() {
                self.has_decoded_data = false;
            }
            return res;
        }
        if buf.len() < U32_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid SASL buffer"));
        }
        let sasl_len = u32::from_be_bytes(buf[0..U32_SIZE].try_into().unwrap());
        if buf.len() - U32_SIZE < sasl_len as usize {
            return Ok(None);
        }
        buf.advance(U32_SIZE);
        let client_opt = &mut *self.client_ctx.lock().expect("client ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        let wrapped = buf.split_to(sasl_len as usize);
        let mut decoded = BytesMut::from(&client_ctx.unwrap(&wrapped)?[..]);
        let res = decode_inner(&mut decoded);
        if res.is_ok() && !decoded.is_empty() && buf.is_empty() {
            buf.extend(decoded);
            self.has_decoded_data = true;
        }
        res
    }
}

fn maybe_wrap(
    codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    let mut out_buf = BytesMut::new();
    write::encode_into(&mut out_buf, outstruct)?;
    let (sasl_wrap, sasl_send_max) = {
        let sasl_param = codec.sasl_param.read().expect("sasl param");
        (sasl_param.0, sasl_param.1)
    };
    if sasl_wrap {
        let client_opt = &mut *codec.client_ctx.lock().expect("client_ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        if sasl_send_max > 0 && out_buf.len() > sasl_send_max as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "buffer too large for SASL: {} > {}",
                    out_buf.len(),
                    sasl_send_max
                ),
            ));
        }
        let sasl_buf = client_ctx.wrap(&out_buf)?;
        let sasl_len = (sasl_buf.len() as u32).to_be_bytes();
        into.extend(&sasl_len);
        into.extend(&*sasl_buf);
    } else {
        into.extend(&out_buf);
    }
    Ok(())
}

impl Encoder<(RequestId, Tag, MaybeControls)> for LdapCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        msg: (RequestId, Tag, MaybeControls),
        into: &mut BytesMut,
    ) -> io::Result<()> {
        let (id, tag, controls) = msg;
        let outstruct = {
            let mut msg = vec![
                Tag::Integer(Integer {
                    inner: id as i64,
                    ..Default::default()
                }),
                tag,
            ];
            if let Some(controls) = controls {
                msg.push(Tag::StructureTag(StructureTag {
                    id: 0,
                    class: TagClass::Context,
                    payload: PL::C(controls.into_iter().map(build_tag).collect()),
                }));
            }
            Tag::Sequence(Sequence {
                inner: msg,
                ..Default::default()
            })
            .into_structure()
        };
        maybe_wrap(self, outstruct, into)?;
        Ok(())
    }
}
