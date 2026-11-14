//! The TCP listeners of the node and the center. On Windows each is bound
//! with `SO_EXCLUSIVEADDRUSE`: without it a program of another account may
//! bind the same address and port with `SO_REUSEADDR` while the service
//! listens there, and take the connections (a browser's login with its
//! token among them). Elsewhere a listener is bound as tokio binds it; Linux
//! gives no other account a port that is listened on.

use std::io;
use std::net::SocketAddr;

use tokio::net::TcpListener;

/// Binds a listener at `addr` (an address and a port, or a name and a
/// port), trying each address the name resolves to as tokio does; the last
/// error when none could be bound.
pub async fn bind(addr: &str) -> io::Result<TcpListener> {
    let mut last = None;
    for at in tokio::net::lookup_host(addr).await? {
        match bind_addr(at) {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the address names no address to listen on",
        )
    }))
}

/// Binds a listener at `at`. It must be called on a tokio runtime.
pub fn bind_addr(at: SocketAddr) -> io::Result<TcpListener> {
    let socket = match at {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    #[cfg(windows)]
    exclusive(&socket)?;
    // What tokio's own bind sets on Unix: a listener started again binds at
    // once, while connections of the one before wait out their time.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(at)?;
    socket.listen(1024)
}

/// Sets `SO_EXCLUSIVEADDRUSE` on `socket`, before it is bound.
#[cfg(windows)]
fn exclusive(socket: &tokio::net::TcpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, setsockopt,
    };
    let on: i32 = 1;
    // SAFETY: a socket this process holds, and an int option of its size.
    let r = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&on as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if r == SOCKET_ERROR {
        // SAFETY: reads this thread's last WinSock error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_listens_on_the_address_and_takes_a_connection() {
        let l = bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        assert!(at.ip().is_loopback() && at.port() != 0);
        let _c = tokio::net::TcpStream::connect(at).await.unwrap();
        let (_s, peer) = l.accept().await.unwrap();
        assert!(peer.ip().is_loopback());
        // A name is resolved; something that is no address is an error.
        assert!(bind("localhost:0").await.is_ok());
        assert!(bind("not an address").await.is_err());
    }

    /// The port a listener holds cannot be taken by a second socket, not even
    /// one that asks for the address to be shared: on Windows that is what
    /// `SO_EXCLUSIVEADDRUSE` refuses.
    #[tokio::test]
    async fn a_second_socket_cannot_take_the_port() {
        for at in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = bind(at).await else {
                // A machine without IPv6.
                continue;
            };
            let held = l.local_addr().unwrap();
            let other = match held {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
            }
            .unwrap();
            other.set_reuseaddr(true).unwrap();
            assert!(other.bind(held).is_err(), "{held} was bound twice");
        }
    }
}
