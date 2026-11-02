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

/// The same lookups through Winsock's `GetAddrInfoW` and `GetNameInfoW`,
/// which MIT's Windows build reaches through its `getaddrinfo` wrappers.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "std has no GetAddrInfoW(AI_CANONNAME) or GetNameInfoW"
)]
pub(crate) fn dns_canonical(host: &str, rdns: bool) -> Option<String> {
    use windows_sys::Win32::Networking::WinSock::{
        FreeAddrInfoW, GetAddrInfoW, GetNameInfoW, WSACleanup, WSAStartup, ADDRINFOW, AI_CANONNAME,
        NI_MAXHOST, NI_NAMEREQD, WSADATA,
    };
    let wide: Vec<u16> = host.encode_utf16().chain(Some(0)).collect();
    if wide[..wide.len() - 1].contains(&0) {
        return None;
    }
    // SAFETY: WSADATA is plain data that WSAStartup fills in.
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: data is a valid out-pointer. Each successful WSAStartup is
    // matched by the WSACleanup below.
    if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
        return None;
    }
    let hints = ADDRINFOW {
        ai_flags: AI_CANONNAME as i32,
        ..Default::default()
    };
    let mut res: *mut ADDRINFOW = std::ptr::null_mut();
    // SAFETY: wide is NUL-terminated, hints is initialized and res is a
    // valid out-pointer; the list it receives is freed below.
    let err = unsafe { GetAddrInfoW(wide.as_ptr(), std::ptr::null(), &hints, &mut res) };
    let mut name = None;
    if err == 0 && !res.is_null() {
        // SAFETY: GetAddrInfoW succeeded, so res points to a valid list that
        // stays alive until FreeAddrInfoW.
        let ai = unsafe { &*res };
        if !ai.ai_canonname.is_null() {
            let mut len = 0;
            // SAFETY: ai_canonname is a NUL-terminated UTF-16 string owned
            // by the list; the loop stops at the NUL.
            while unsafe { *ai.ai_canonname.add(len) } != 0 {
                len += 1;
            }
            // SAFETY: the first len units of ai_canonname were just read.
            let canon = unsafe { std::slice::from_raw_parts(ai.ai_canonname, len) };
            name = Some(String::from_utf16_lossy(canon));
        }
        if rdns {
            let mut buf = [0u16; NI_MAXHOST as usize];
            let addrlen = i32::try_from(ai.ai_addrlen).unwrap_or(0);
            // SAFETY: ai_addr/ai_addrlen describe a valid socket address and
            // buf is writable for NI_MAXHOST units; no service is requested.
            let err = unsafe {
                GetNameInfoW(
                    ai.ai_addr,
                    addrlen,
                    buf.as_mut_ptr(),
                    NI_MAXHOST,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD as i32,
                )
            };
            if err == 0 {
                let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                name = Some(String::from_utf16_lossy(&buf[..len]));
            }
        }
        // SAFETY: res came from a successful GetAddrInfoW and is freed once.
        unsafe { FreeAddrInfoW(res) };
    }
    // SAFETY: balances the successful WSAStartup above.
    unsafe { WSACleanup() };
    name
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn dns_canonical(_host: &str, _rdns: bool) -> Option<String> {
    None
}

#[cfg(all(test, windows))]
mod tests {
    use super::dns_canonical;

    /// Needs `127.0.0.1 hostsreal.example.test hostsalias` in the hosts
    /// file, as the `windows` CI job adds.
    #[test]
    #[ignore = "needs a hosts-file entry"]
    fn winsock_canonicalizes_hosts_file_names() {
        let real = dns_canonical("hostsreal.example.test", false);
        let alias = dns_canonical("hostsalias", false);
        let reverse = dns_canonical("hostsalias", true);
        eprintln!("hostsreal={real:?} hostsalias={alias:?} rdns={reverse:?}");
        assert_eq!(real.as_deref(), Some("hostsreal.example.test"));
        assert!(alias.is_some_and(|n| !n.is_empty()));
        assert!(reverse.is_some_and(|n| !n.is_empty()));
        assert_eq!(dns_canonical("missing.invalid", false), None);
    }
}
