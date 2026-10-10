#!/usr/bin/env python3
"""MIT GSS-API oracle for krb5-rs interop tests.

Runs inside the KDC container on top of python3-gssapi, which binds MIT's
libgssapi_krb5. It lets the Rust integration tests exercise our RFC 4121
initiator/acceptor and SPNEGO against the real MIT implementation.

Wire protocol (TCP, one GSS context per connection): every message is a
4-byte big-endian length followed by a payload. Client payloads start with a
one-byte command; server replies start with a status byte: b"C" (complete),
b"N" (continue needed), b"E" (error; rest is UTF-8 text).

Commands (acceptor side, MIT accepts what krb5-rs initiated):
  b"A" token                 accept_sec_context step (krb5 or SPNEGO token)
  b"B" u32be(len) appdata token
                             same, with channel bindings application_data
Commands (initiator side, MIT initiates, krb5-rs accepts):
  b"I" flagbyte              start init_sec_context to HTTP/server.test.realm
                             flagbyte bit0 = delegate, bit1 = use SPNEGO,
                             bit2 = request channel-bound (GSS_C_CHANNEL_BOUND)
  b"R" token                 feed the acceptor's reply token into init
Commands (established context):
  b"W" data                  wrap confidential           -> C token
  b"P" data                  wrap integrity-only         -> C token
  b"U" token                 unwrap                      -> C confbyte data
  b"M" data                  get_mic                     -> C mic
  b"V" u32be(len) data mic   verify_mic                  -> C or E
  b"Q"                       inquire: C json{"src","tgt","flags","mech",
                             "lifetime","deleg_name"}
On b"C" for A/B/I/R the reply is: status, u32be(out_token_len), out_token,
then the same JSON as Q.
"""
import json
import os
import socket
import struct
import sys
import threading
import traceback

import gssapi
from gssapi.raw import ChannelBindings
from gssapi.raw import acquire_cred_with_password as _acq_pw
from gssapi.raw import inquire_context as _inquire
from gssapi.raw.misc import GSSError

SERVICE = "HTTP/server.test.realm@TEST.REALM"
USER = os.environ.get("ORACLE_USER", "testuser@TEST.REALM")
PASSWORD = os.environ.get("ORACLE_PASSWORD", "testpassword")
PORT = int(os.environ.get("ORACLE_PORT", "10189"))

KRB5_OID = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")
SPNEGO_OID = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")
# MIT: GSS_C_CHANNEL_BOUND_FLAG (include/gssapi/gssapi_ext.h) = 0x0800
CHANNEL_BOUND_FLAG = 0x0800


def recv_msg(sock):
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    return recv_exact(sock, n)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_msg(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


class Session:
    def __init__(self):
        self.ctx = None
        self.deleg_name = None
        self.initiating = False

    def info(self):
        out = {}
        if self.ctx is None:
            return out
        try:
            res = _inquire(self.ctx)
            out["src"] = str(gssapi.Name(res.initiator_name)) if res.initiator_name else None
            out["tgt"] = str(gssapi.Name(res.target_name)) if res.target_name else None
            out["flags"] = int(res.flags)
            out["mech"] = res.mech.dotted_form if res.mech else None
            out["lifetime"] = int(res.lifetime)
            out["complete"] = bool(res.complete)
        except GSSError as e:
            out["inquire_error"] = str(e)
        out["deleg_name"] = self.deleg_name
        return out

    # ---- acceptor ----
    def accept(self, token, appdata=None):
        if self.ctx is None:
            name = gssapi.Name(SERVICE, gssapi.NameType.kerberos_principal)
            creds = gssapi.Credentials(name=name, usage="accept")
            cb = None
            if appdata is not None:
                cb = ChannelBindings(application_data=appdata)
            self.ctx = gssapi.SecurityContext(creds=creds, usage="accept",
                                              channel_bindings=cb)
        out = self.ctx.step(token)
        if self.ctx.complete and self.ctx.delegated_creds is not None:
            self.deleg_name = str(self.ctx.delegated_creds.name)
        return out or b""

    # ---- initiator ----
    def init_start(self, flagbyte):
        delegate = bool(flagbyte & 1)
        spnego = bool(flagbyte & 2)
        channel_bound = bool(flagbyte & 4)
        user = gssapi.Name(USER, gssapi.NameType.kerberos_principal)
        raw = _acq_pw(user, PASSWORD.encode(), usage="initiate",
                      mechs=[SPNEGO_OID if spnego else KRB5_OID])
        creds = gssapi.Credentials(base=raw.creds)
        target = gssapi.Name(SERVICE, gssapi.NameType.kerberos_principal)
        flags = (gssapi.RequirementFlag.mutual_authentication
                 | gssapi.RequirementFlag.integrity
                 | gssapi.RequirementFlag.confidentiality
                 | gssapi.RequirementFlag.replay_detection
                 | gssapi.RequirementFlag.out_of_sequence_detection)
        flags = int(flags)
        if delegate:
            flags |= int(gssapi.RequirementFlag.delegate_to_peer)
        if channel_bound:
            flags |= CHANNEL_BOUND_FLAG
        self.ctx = gssapi.SecurityContext(
            name=target, creds=creds, usage="initiate", flags=flags,
            mech=SPNEGO_OID if spnego else KRB5_OID)
        self.initiating = True
        return self.ctx.step() or b""

    def init_step(self, token):
        return self.ctx.step(token) or b""

    # ---- per-message ----
    def wrap(self, data, conf):
        res = gssapi.raw.wrap(self.ctx, data, confidential=conf)
        return res.message

    def unwrap(self, token):
        res = gssapi.raw.unwrap(self.ctx, token)
        return (b"\x01" if res.encrypted else b"\x00") + res.message

    def get_mic(self, data):
        return gssapi.raw.get_mic(self.ctx, data)

    def verify_mic(self, data, mic):
        gssapi.raw.verify_mic(self.ctx, data, mic)


def ctx_reply(sess, out_token):
    status = b"C" if sess.ctx.complete else b"N"
    return (status + struct.pack(">I", len(out_token)) + out_token
            + json.dumps(sess.info()).encode())


def handle(conn):
    sess = Session()
    while True:
        msg = recv_msg(conn)
        if msg is None:
            return
        cmd, body = msg[:1], msg[1:]
        try:
            if cmd == b"A":
                send_msg(conn, ctx_reply(sess, sess.accept(body)))
            elif cmd == b"B":
                (n,) = struct.unpack(">I", body[:4])
                appdata, token = body[4:4 + n], body[4 + n:]
                send_msg(conn, ctx_reply(sess, sess.accept(token, appdata)))
            elif cmd == b"I":
                send_msg(conn, ctx_reply(sess, sess.init_start(body[0])))
            elif cmd == b"R":
                send_msg(conn, ctx_reply(sess, sess.init_step(body)))
            elif cmd == b"W":
                send_msg(conn, b"C" + sess.wrap(body, True))
            elif cmd == b"P":
                send_msg(conn, b"C" + sess.wrap(body, False))
            elif cmd == b"U":
                send_msg(conn, b"C" + sess.unwrap(body))
            elif cmd == b"M":
                send_msg(conn, b"C" + sess.get_mic(body))
            elif cmd == b"V":
                (n,) = struct.unpack(">I", body[:4])
                sess.verify_mic(body[4:4 + n], body[4 + n:])
                send_msg(conn, b"C")
            elif cmd == b"Q":
                send_msg(conn, b"C" + json.dumps(sess.info()).encode())
            else:
                send_msg(conn, b"E" + f"unknown command {cmd!r}".encode())
        except GSSError as e:
            send_msg(conn, b"E" + (
                f"GSSError major={e.maj_code} minor={e.min_code}: {e}"
            ).encode())
        except Exception as e:  # noqa: BLE001 — report anything to the test
            traceback.print_exc()
            send_msg(conn, b"E" + f"{type(e).__name__}: {e}".encode())


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(8)
    print(f"gss_oracle listening on {PORT}", file=sys.stderr, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def serve(conn):
    try:
        handle(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
