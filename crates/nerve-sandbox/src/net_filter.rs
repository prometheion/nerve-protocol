//! The seccomp filter that keeps a command off the network, for the owner's
//! network switch (`nerve-node folder network off`): a command and all it
//! starts make no socket but a unix one. The socket a call would make is
//! refused where it is made, whatever it would be for (TCP, UDP, raw,
//! packet, netlink and every other domain), so no address is ever judged.
//! io_uring is refused as well: its operations make and use sockets
//! without the calls this filter judges.
//!
//! The filter is a small BPF program written here, put on the command
//! between `fork` and `exec` ([`Filter::install`]); `no_new_privs` comes
//! first, which the kernel wants of an account without `CAP_SYS_ADMIN`.
//! A call of another architecture than the node's (the 32-bit calls an
//! x86_64 or aarch64 kernel also takes, and x86_64's x32 calls) has other
//! numbers than those judged here, so the filter ends the process that
//! makes one rather than let it through.
//!
//! What it does not hold: a unix socket leads wherever the program
//! listening on it leads, and a socket another process hands over on one
//! is used as it is. Landlock keeps the command off the unix sockets
//! outside its folders where the kernel has the rule for them (ABI 9).

use std::io;

/// What a socket call of a refused domain answers: the system does not let
/// the account make it.
const REFUSED: u32 = libc::SECCOMP_RET_ERRNO | libc::EACCES as u32;

/// What io_uring answers: as a kernel without it, so that a program falls
/// back on plain calls, which the filter judges.
const NO_URING: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;

/// A call of another architecture: nothing of it is judged, so the process
/// ends.
const FOREIGN: u32 = libc::SECCOMP_RET_KILL_PROCESS;

/// The socket domains a command keeps: unix sockets alone, which reach
/// only programs on this machine.
const KEPT_DOMAINS: &[i32] = &[libc::AF_UNIX];

/// The architecture the filter judges the calls of (`AUDIT_ARCH_*` of
/// `linux/audit.h`): the node's own. `None` where no filter is written for
/// it, or the machine is big-endian (the domain is read from the low half
/// of the call's first argument as a little-endian machine lays it out).
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
const ARCH: Option<u32> = Some(0xc000_003e);
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
const ARCH: Option<u32> = Some(0xc000_00b7);
#[cfg(not(any(
    all(target_arch = "x86_64", target_endian = "little"),
    all(target_arch = "aarch64", target_endian = "little")
)))]
const ARCH: Option<u32> = None;

/// x86_64's x32 calls come with the x86_64 architecture and this bit in
/// their number.
#[cfg(target_arch = "x86_64")]
const X32_BIT: u32 = 0x4000_0000;

/// Where a jump of the program goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum To {
    Next,
    Domain,
    Allow,
    NoUring,
    Foreign,
}

/// One instruction of the program as it is written, its jumps by name; the
/// names are placed with `At`, which takes no room.
enum Ins {
    Load(u32),
    Jeq(u32, To, To),
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    Jge(u32, To, To),
    Ret(u32),
    At(To),
}

/// The filter for a command off the network, made before the `fork` so
/// that its installing allocates nothing.
#[derive(Debug, Clone)]
pub struct Filter(Vec<libc::sock_filter>);

impl Filter {
    /// The filter for this machine's architecture; `None` where there is
    /// none ([`ARCH`]).
    pub fn no_network() -> Option<Filter> {
        let arch = ARCH?;
        let nr = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
        let arch_at = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
        // The low half of the first argument, the domain, which the kernel
        // takes as an int.
        let domain = std::mem::offset_of!(libc::seccomp_data, args) as u32;
        let mut p = vec![
            Ins::Load(arch_at),
            Ins::Jeq(arch, To::Next, To::Foreign),
            Ins::Load(nr),
        ];
        #[cfg(target_arch = "x86_64")]
        p.push(Ins::Jge(X32_BIT, To::Foreign, To::Next));
        for call in [libc::SYS_socket, libc::SYS_socketpair] {
            p.push(Ins::Jeq(call as u32, To::Domain, To::Next));
        }
        for call in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            p.push(Ins::Jeq(call as u32, To::NoUring, To::Next));
        }
        p.extend([Ins::Ret(ALLOW), Ins::At(To::Domain), Ins::Load(domain)]);
        for d in KEPT_DOMAINS {
            p.push(Ins::Jeq(*d as u32, To::Allow, To::Next));
        }
        p.extend([
            Ins::Ret(REFUSED),
            Ins::At(To::Allow),
            Ins::Ret(ALLOW),
            Ins::At(To::NoUring),
            Ins::Ret(NO_URING),
            Ins::At(To::Foreign),
            Ins::Ret(FOREIGN),
        ]);
        Some(Filter(assemble(&p)))
    }

    /// Puts the filter on the calling thread and on all it starts, after
    /// `no_new_privs`, which keeps a program that would gain rights at
    /// `exec` (a set-user-ID one) from starting without it. Only system
    /// calls, so it may run between `fork` and `exec`.
    pub fn install(&self) -> io::Result<()> {
        let prog = libc::sock_fprog {
            len: self.0.len() as u16,
            filter: self.0.as_ptr().cast_mut(),
        };
        // SAFETY: prctl with integer arguments; the program outlives the
        // call, which copies it into the kernel.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &prog as *const libc::sock_fprog,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Whether this machine can put the filter on a command: a filter for its
/// architecture, and a kernel that takes seccomp filters with the answers
/// it gives.
pub fn available() -> bool {
    Filter::no_network().is_some()
        && [libc::SECCOMP_RET_ERRNO, libc::SECCOMP_RET_KILL_PROCESS]
            .iter()
            .all(|action| {
                // SAFETY: the query reads the u32 it is given.
                unsafe {
                    libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_GET_ACTION_AVAIL,
                        0,
                        action as *const u32,
                    ) == 0
                }
            })
}

/// The BPF instructions of `p`, its jumps counted from the instruction
/// after them.
fn assemble(p: &[Ins]) -> Vec<libc::sock_filter> {
    let mut places = Vec::new();
    let mut n = 0usize;
    for i in p {
        match i {
            Ins::At(to) => places.push((*to, n)),
            _ => n += 1,
        }
    }
    let at = |to: To, from: usize| -> u8 {
        if to == To::Next {
            return 0;
        }
        let (_, place) = places
            .iter()
            .find(|(t, _)| *t == to)
            .expect("a placed name");
        u8::try_from(place - from - 1).expect("a short jump")
    };
    let mut out = Vec::new();
    for i in p {
        let here = out.len();
        let (code, jt, jf, k) = match *i {
            Ins::Load(k) => (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, k),
            Ins::Jeq(k, t, f) => (
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                at(t, here),
                at(f, here),
                k,
            ),
            Ins::Jge(k, t, f) => (
                libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
                at(t, here),
                at(f, here),
                k,
            ),
            Ins::Ret(k) => (libc::BPF_RET | libc::BPF_K, 0, 0, k),
            Ins::At(_) => continue,
        };
        out.push(libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// What the kernel would answer a call `nr` of `arch` whose first
    /// argument is `arg0`: the filter run as the kernel runs it, for the
    /// instructions it has.
    fn judge(f: &Filter, arch: u32, nr: u32, arg0: u64) -> u32 {
        let mut data = [0u8; std::mem::size_of::<libc::seccomp_data>()];
        let put = |data: &mut [u8], at: usize, b: &[u8]| data[at..at + b.len()].copy_from_slice(b);
        put(
            &mut data,
            std::mem::offset_of!(libc::seccomp_data, nr),
            &nr.to_ne_bytes(),
        );
        put(
            &mut data,
            std::mem::offset_of!(libc::seccomp_data, arch),
            &arch.to_ne_bytes(),
        );
        put(
            &mut data,
            std::mem::offset_of!(libc::seccomp_data, args),
            &arg0.to_ne_bytes(),
        );
        let (mut pc, mut a) = (0usize, 0u32);
        loop {
            let i = f.0[pc];
            let code = u32::from(i.code);
            pc += 1;
            if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
                let at = i.k as usize;
                a = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
            } else if code == libc::BPF_RET | libc::BPF_K {
                return i.k;
            } else {
                let taken = match code {
                    c if c == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K => a == i.k,
                    c if c == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K => a >= i.k,
                    c => panic!("an instruction the filter has no use for: {c:#x}"),
                };
                pc += usize::from(if taken { i.jt } else { i.jf });
            }
        }
    }

    fn filter() -> Option<(Filter, u32)> {
        Some((Filter::no_network()?, ARCH?))
    }

    /// Every socket domain the kernel knows but unix is refused, by
    /// `socket` and by `socketpair`, whatever the upper half of the
    /// argument holds (the kernel takes the domain as an int).
    #[test]
    fn the_filter_refuses_every_socket_but_a_unix_one() {
        let Some((f, arch)) = filter() else {
            eprintln!("no filter for this architecture; skipped");
            return;
        };
        for call in [libc::SYS_socket, libc::SYS_socketpair] {
            let call = call as u32;
            assert_eq!(judge(&f, arch, call, libc::AF_UNIX as u64), ALLOW);
            assert_eq!(judge(&f, arch, call, 1 << 32 | libc::AF_UNIX as u64), ALLOW);
            for d in [
                libc::AF_INET,
                libc::AF_INET6,
                libc::AF_PACKET,
                libc::AF_NETLINK,
                libc::AF_VSOCK,
                libc::AF_BLUETOOTH,
                libc::AF_XDP,
                libc::AF_ALG,
            ] {
                assert_eq!(judge(&f, arch, call, d as u64), REFUSED, "domain {d}");
            }
            // Every other number, known or not.
            for d in 0..=64u64 {
                let want = if d == libc::AF_UNIX as u64 {
                    ALLOW
                } else {
                    REFUSED
                };
                assert_eq!(judge(&f, arch, call, d), want, "domain {d}");
            }
        }
        // Other calls pass whatever their argument.
        assert_eq!(
            judge(&f, arch, libc::SYS_read as u32, libc::AF_INET as u64),
            ALLOW
        );
    }

    #[test]
    fn the_filter_refuses_io_uring() {
        let Some((f, arch)) = filter() else {
            eprintln!("no filter for this architecture; skipped");
            return;
        };
        for call in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert_eq!(judge(&f, arch, call as u32, 0), NO_URING, "call {call}");
        }
    }

    /// A call of the 32-bit architecture of the same machine (x86 on
    /// x86_64, ARM on aarch64), of any other, and x86_64's x32 calls, runs
    /// nothing: the process ends.
    #[test]
    fn a_call_of_another_architecture_ends_the_process() {
        let Some((f, arch)) = filter() else {
            eprintln!("no filter for this architecture; skipped");
            return;
        };
        // AUDIT_ARCH_I386, AUDIT_ARCH_ARM, AUDIT_ARCH_X86_64 and
        // AUDIT_ARCH_AARCH64.
        for other in [0x4000_0003u32, 0x4000_0028, 0xc000_003e, 0xc000_00b7] {
            if other == arch {
                continue;
            }
            for nr in [0, 1, 41, 102, 281, 359] {
                assert_eq!(
                    judge(&f, other, nr, 1),
                    FOREIGN,
                    "arch {other:#x} call {nr}"
                );
            }
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_read as u32, libc::SYS_socket as u32] {
            assert_eq!(judge(&f, arch, X32_BIT | nr, 1), FOREIGN, "x32 call {nr}");
        }
    }

    /// What a process that probes the sockets finds, as bits: one for each
    /// of [`PROBES`] whose `socket` call failed with `EACCES`, and the last
    /// for an io_uring that failed with `ENOSYS`. It probes in the child,
    /// with the filter put on it first when `filtered`.
    fn probed(filtered: bool) -> i32 {
        let f = Filter::no_network().unwrap();
        let mut cmd = std::process::Command::new("/bin/true");
        // SAFETY: only system calls, and errno, in the child.
        unsafe {
            cmd.pre_exec(move || {
                if filtered {
                    f.install()?;
                }
                let mut bits = 0;
                for (i, (domain, kind)) in PROBES.iter().enumerate() {
                    let fd = libc::socket(*domain, *kind, 0);
                    if fd >= 0 {
                        libc::close(fd);
                    } else if *libc::__errno_location() == libc::EACCES {
                        bits |= 1 << i;
                    }
                }
                let mut params = [0u8; 120];
                let r = libc::syscall(libc::SYS_io_uring_setup, 1, params.as_mut_ptr());
                if r >= 0 {
                    libc::close(r as i32);
                } else if *libc::__errno_location() == libc::ENOSYS {
                    bits |= 1 << PROBES.len();
                }
                libc::_exit(bits);
            });
        }
        cmd.status().unwrap().code().unwrap()
    }

    const PROBES: [(i32, i32); 7] = [
        (libc::AF_UNIX, libc::SOCK_STREAM),
        (libc::AF_UNIX, libc::SOCK_DGRAM),
        (libc::AF_INET, libc::SOCK_STREAM),
        (libc::AF_INET, libc::SOCK_DGRAM),
        (libc::AF_INET6, libc::SOCK_DGRAM),
        (libc::AF_NETLINK, libc::SOCK_RAW),
        (libc::AF_PACKET, libc::SOCK_RAW),
    ];

    /// The kernel holds a process to the filter: it makes unix sockets and
    /// no other, and has no io_uring, which it has without the filter (or
    /// is refused by the kernel itself, not with `ENOSYS`). Skipped where
    /// the kernel takes no filter.
    #[test]
    fn a_process_under_the_filter_makes_unix_sockets_only() {
        if !available() {
            eprintln!("no seccomp filters here; skipped");
            return;
        }
        let all = (1 << (PROBES.len() + 1)) - 1;
        assert_eq!(probed(true), all & !0b11, "{:b}", probed(true));
        // Without it the same process makes TCP and UDP sockets.
        assert_eq!(probed(false) & 0b11100, 0, "{:b}", probed(false));
    }

    /// A command under the filter opens no TCP connection and no UDP
    /// socket, which it opens without; and runs as it would otherwise.
    /// Skipped where the kernel takes no filter, or there is no bash to
    /// connect with (`/dev/tcp`, `/dev/udp`).
    #[test]
    fn a_command_under_the_filter_opens_no_tcp_or_udp_socket() {
        if !available() || !std::path::Path::new("/bin/bash").exists() {
            eprintln!("no seccomp filters or no bash here; skipped");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let run = |filtered: bool, script: &str| {
            let f = Filter::no_network().unwrap();
            let mut cmd = std::process::Command::new("/bin/bash");
            cmd.arg("-c").arg(script);
            // SAFETY: the filter's system calls alone, in the child.
            unsafe {
                cmd.pre_exec(move || if filtered { f.install() } else { Ok(()) });
            }
            cmd.status().unwrap().success()
        };
        let tcp = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
        let udp = format!("exec 3<>/dev/udp/127.0.0.1/{udp_port} && echo x >&3");
        assert!(run(false, &tcp));
        assert!(run(false, &udp));
        assert!(!run(true, &tcp));
        assert!(!run(true, &udp));
        assert!(run(true, "cat /etc/passwd > /dev/null"));
    }
}
