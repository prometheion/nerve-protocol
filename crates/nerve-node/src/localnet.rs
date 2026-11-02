//! This machine's own addresses, for the web UI's check of who connects
//! (crate::webui::peer).

use std::net::IpAddr;

/// The addresses of every interface of this machine, in the node's network
/// namespace; none when they cannot be read.
pub(crate) fn addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a list it allocated, which is
    // read while it lives and given back to freeifaddrs once.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut at = list;
        while !at.is_null() {
            let a = (*at).ifa_addr;
            if !a.is_null() {
                match i32::from((*a).sa_family) {
                    libc::AF_INET => {
                        let v4 = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::from(v4.sin_addr.s_addr.to_ne_bytes()));
                    }
                    libc::AF_INET6 => {
                        let v6 = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::from(v6.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            at = (*at).ifa_next;
        }
        libc::freeifaddrs(list);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_is_one_of_them() {
        let own = super::addresses();
        assert!(own.iter().any(|a| a.is_loopback()), "{own:?}");
    }
}
