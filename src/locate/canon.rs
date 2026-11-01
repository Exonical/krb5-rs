//! Host-name canonicalization lookups of MIT `expand_hostname`
//! (os/sn2princ.c:89-153), shared by the client and kprop.

/// Forward lookup with `AI_CANONNAME`, then optionally a reverse lookup of
/// the first address, as `expand_hostname` does.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "std has no getaddrinfo(AI_CANONNAME) or getnameinfo"
)]
pub(crate) fn dns_canonical(host: &str, rdns: bool) -> Option<String> {
    use std::ffi::{CStr, CString};
    let c_host = CString::new(host).ok()?;
    // SAFETY: an all-zero addrinfo is a valid "no constraints" hints value.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_CANONNAME;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: c_host is NUL-terminated, hints is initialized and res is a
    // valid out-pointer; the list it receives is freed below.
    let err = unsafe { libc::getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if err != 0 || res.is_null() {
        return None;
    }
    // SAFETY: getaddrinfo succeeded, so res points to a valid list that
    // stays alive until freeaddrinfo.
    let ai = unsafe { &*res };
    let mut name = None;
    if !ai.ai_canonname.is_null() {
        // SAFETY: ai_canonname is a NUL-terminated string owned by the list.
        let canon = unsafe { CStr::from_ptr(ai.ai_canonname) };
        name = Some(canon.to_string_lossy().into_owned());
    }
    if rdns {
        let mut buf = [0 as libc::c_char; 1025];
        let len = libc::socklen_t::try_from(buf.len()).unwrap_or(0);
        // SAFETY: ai_addr/ai_addrlen describe a valid socket address and
        // buf is writable for len bytes; no service buffer is requested.
        let err = unsafe {
            libc::getnameinfo(
                ai.ai_addr,
                ai.ai_addrlen,
                buf.as_mut_ptr(),
                len,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        if err == 0 {
            // SAFETY: getnameinfo NUL-terminates buf on success.
            let reverse = unsafe { CStr::from_ptr(buf.as_ptr()) };
            name = Some(reverse.to_string_lossy().into_owned());
        }
    }
    // SAFETY: res came from a successful getaddrinfo and is freed once.
    unsafe { libc::freeaddrinfo(res) };
    name
}

#[cfg(not(unix))]
pub(crate) fn dns_canonical(_host: &str, _rdns: bool) -> Option<String> {
    None
}
