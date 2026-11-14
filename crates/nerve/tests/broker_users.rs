//! The broker on Windows when the app's user is a standard user: the UAC
//! prompt then asks for an administrator's name and password, and the
//! broker runs as that administrator, another account than the app's. The
//! app must reach it all the same, and the broker's commands must take the
//! app's user, not the administrator, as the one who asked.
//!
//! Run by hand on a Windows test machine, as a standard user, with an
//! administrator's name and password in `NERVE_TEST_ADMIN` and
//! `NERVE_TEST_ADMIN_PASSWORD`, and the program in a folder the
//! administrator may run it from in `NERVE_DESKTOP_EXE`. The broker is
//! started here with those credentials instead of the UAC prompt (it then
//! runs as the administrator, though not elevated), and the app's side is
//! the app's own code.

#![cfg(windows)]

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessWithLogonW, LOGON_WITH_PROFILE, PROCESS_INFORMATION,
    STARTUPINFOW,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

#[test]
#[ignore = "needs a standard user to run it and an administrator's name and password (NERVE_TEST_ADMIN, NERVE_TEST_ADMIN_PASSWORD)"]
fn a_standard_users_app_reaches_the_broker_of_an_administrator() {
    let admin = std::env::var("NERVE_TEST_ADMIN").unwrap();
    let password = std::env::var("NERVE_TEST_ADMIN_PASSWORD").unwrap();
    let exe =
        std::env::var("NERVE_DESKTOP_EXE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_nerve").into());
    let (name, args) = nerve::broker::win::broker_args().unwrap();
    let mut line = wide(&format!("\"{exe}\" {args}"));
    let dir = std::path::Path::new(&exe).parent().unwrap();
    // SAFETY: filled structures and strings that live across the call; the
    // thread handle it gives is closed, the process handle goes to connect.
    let process = unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessWithLogonW(
            wide(&admin).as_ptr(),
            wide(".").as_ptr(),
            wide(&password).as_ptr(),
            LOGON_WITH_PROFILE,
            std::ptr::null(),
            line.as_mut_ptr(),
            CREATE_NO_WINDOW,
            std::ptr::null(),
            wide(&dir.display().to_string()).as_ptr(),
            &si,
            &mut pi,
        );
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        CloseHandle(pi.hThread);
        pi.hProcess
    };
    // SAFETY: the broker's process handle, given away.
    let (requests, answers) = unsafe { nerve::broker::win::connect(&name, process, true) }.unwrap();
    let client = nerve::broker::Client::start(Box::new(answers), Box::new(requests), None).unwrap();
    let out = client.run(vec!["--version".into()], None).unwrap();
    assert!(out.ok, "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("nerve"),
        "{out:?}"
    );
}
