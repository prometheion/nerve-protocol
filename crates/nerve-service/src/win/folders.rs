//! The machine's own folders (the Windows folder, System32, `ProgramData`,
//! `Program Files`) as Windows keeps them, never as the environment says:
//! an administrator's elevated terminal takes `SystemRoot` and
//! `ProgramData` from the account's own variables, which the same person's
//! unelevated programs (an agent's shell command among them) may set
//! (round 6, security 1). Where `sudo` resets the environment on Linux,
//! these read the kernel and the machine's part of the registry, which
//! only the administrators change.

use std::path::PathBuf;

/// The drive of the Windows folder `windows` (`C:` of `C:\Windows`), which
/// is what `%SystemDrive%` stands for; `C:` where it names none.
pub fn drive_of(windows: &str) -> String {
    match windows.as_bytes() {
        [d, b':', ..] if d.is_ascii_alphabetic() => windows[..2].to_string(),
        _ => "C:".into(),
    }
}

/// The registry's text `raw` of a machine folder (`%SystemDrive%\ProgramData`)
/// with `%SystemDrive%` replaced by `drive`; `None` where any other
/// variable is left in it, or it is no whole path, so the caller takes the
/// folder's usual place on that drive.
pub fn expand_drive(raw: &str, drive: &str) -> Option<PathBuf> {
    const NAME: &str = "%systemdrive%";
    let text = match raw.get(..NAME.len()) {
        Some(head) if head.eq_ignore_ascii_case(NAME) => format!("{drive}{}", &raw[NAME.len()..]),
        _ => raw.to_string(),
    };
    let whole = matches!(text.as_bytes(), [d, b':', b'\\', ..] if d.is_ascii_alphabetic());
    (whole && !text.contains('%')).then(|| PathBuf::from(text))
}

/// The variables that steer where a program downloads from and whom it
/// trusts there: an administrator's command takes none of them from the
/// account's own environment (round 7, security 2).
pub const STEERING: [&str; 6] = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

/// Whether the environment variable `name` is one of [`STEERING`]; Windows
/// does not tell cases apart in a name.
pub fn is_steering(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    STEERING.iter().any(|s| s.eq_ignore_ascii_case(&name))
}

#[cfg(windows)]
pub use sys::{program_data, program_files, system32, take_machine_environment, windows_dir};

#[cfg(windows)]
mod sys {
    use std::path::PathBuf;

    use super::{drive_of, expand_drive};
    use crate::win::sid::{from_wide, wide};

    /// What a call of the `GetSystemDirectoryW` kind wrote, which reads no
    /// variable; `None` when it failed.
    fn kernel_folder(call: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Option<PathBuf> {
        let mut buf = vec![0u16; 260];
        loop {
            // SAFETY: a buffer of the length given; the call writes at most
            // that many characters with the NUL, or says how many it needs.
            let n = unsafe { call(buf.as_mut_ptr(), buf.len() as u32) } as usize;
            match n {
                0 => return None,
                n if n < buf.len() => {
                    // SAFETY: the call ended the text with a NUL.
                    return Some(PathBuf::from(unsafe { from_wide(buf.as_ptr()) }));
                }
                n => buf.resize(n + 1, 0),
            }
        }
    }

    /// The Windows folder (`C:\Windows`).
    pub fn windows_dir() -> PathBuf {
        use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
        kernel_folder(GetSystemWindowsDirectoryW).unwrap_or_else(|| "C:\\Windows".into())
    }

    /// The system folder (`C:\Windows\System32`).
    pub fn system32() -> PathBuf {
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
        kernel_folder(GetSystemDirectoryW).unwrap_or_else(|| windows_dir().join("System32"))
    }

    /// The folder `%ProgramData%` stands for (`C:\ProgramData`).
    pub fn program_data() -> PathBuf {
        machine_folder(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            "ProgramData",
            "ProgramData",
        )
    }

    /// The folder `%ProgramFiles%` stands for (`C:\Program Files`).
    pub fn program_files() -> PathBuf {
        machine_folder(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            "ProgramFilesDir",
            "Program Files",
        )
    }

    /// Replaces the [`STEERING`] variables of this process by the
    /// machine's own (`HKLM\SYSTEM\CurrentControlSet\Control\Session
    /// Manager\Environment`, which only the administrators change), as
    /// `sudo` resets them on Linux: an elevated terminal takes the
    /// account's, which any unelevated program of the account writes. A
    /// company's proxy is a machine variable, and its TLS inspection puts
    /// its root into the Windows store, which needs no variable. A value
    /// that names another variable (`%x%`) is not taken, since that would
    /// read the account's.
    ///
    /// # Safety
    ///
    /// Changes the environment: call it before this process starts
    /// another thread.
    pub unsafe fn take_machine_environment() {
        let set: Vec<_> = std::env::vars_os()
            .map(|(k, _)| k)
            .filter(|k| super::is_steering(k))
            .collect();
        // SAFETY: the caller's promise.
        unsafe {
            for k in set {
                std::env::remove_var(k);
            }
            for name in super::STEERING {
                let key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
                if let Some(v) = machine_text(key, name).filter(|v| !v.contains('%')) {
                    std::env::set_var(name, v);
                }
            }
        }
    }

    /// The folder the machine's registry names at `key`, `value`, with
    /// `%SystemDrive%` taken from the Windows folder; `usual` on that drive
    /// where it cannot be read.
    fn machine_folder(key: &str, value: &str, usual: &str) -> PathBuf {
        let drive = drive_of(&windows_dir().to_string_lossy());
        machine_text(key, value)
            .and_then(|raw| expand_drive(&raw, &drive))
            .unwrap_or_else(|| PathBuf::from(format!("{drive}\\{usual}")))
    }

    /// The text at `key`, `value` below `HKEY_LOCAL_MACHINE`, as it is
    /// stored: an expandable string is not expanded, since that would read
    /// the variables.
    fn machine_text(key: &str, value: &str) -> Option<String> {
        use windows_sys::Win32::System::Registry::{
            HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegGetValueW,
        };
        let (key, value) = (wide(key), wide(value));
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
        let mut len = 0u32;
        // SAFETY: a null buffer asks for the size, the second call fills one
        // of that size and ends it with a NUL.
        unsafe {
            if RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut len,
            ) != 0
            {
                return None;
            }
            let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
            let mut len = (buf.len() * 2) as u32;
            if RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            ) != 0
            {
                return None;
            }
            Some(from_wide(buf.as_ptr())).filter(|t| !t.is_empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `%SystemDrive%` is the Windows folder's drive, in any case; any other
    /// variable, or a text that is no whole path, is not taken.
    #[test]
    fn the_system_drive_is_the_windows_folder_s() {
        assert_eq!(drive_of(r"D:\Windows"), "D:");
        assert_eq!(drive_of(""), "C:");
        assert_eq!(
            expand_drive(r"%SystemDrive%\ProgramData", "D:"),
            Some(PathBuf::from(r"D:\ProgramData"))
        );
        assert_eq!(
            expand_drive(r"%SYSTEMDRIVE%\ProgramData", "E:"),
            Some(PathBuf::from(r"E:\ProgramData"))
        );
        assert_eq!(
            expand_drive(r"C:\Program Files", "D:"),
            Some(PathBuf::from(r"C:\Program Files"))
        );
        assert_eq!(expand_drive(r"%USERPROFILE%\ProgramData", "C:"), None);
        assert_eq!(expand_drive(r"%SystemDrive%\%x%", "C:"), None);
        assert_eq!(expand_drive(r"ProgramData", "C:"), None);
    }

    /// The variables of the steering kind are the ones an administrator's
    /// command drops, in any case.
    #[test]
    fn the_steering_variables_are_named() {
        use std::ffi::OsStr;
        for n in [
            "SSL_CERT_FILE",
            "ssl_cert_dir",
            "Https_Proxy",
            "NO_PROXY",
            "all_proxy",
        ] {
            assert!(is_steering(OsStr::new(n)), "{n}");
        }
        for n in ["PATH", "ProgramData", "NERVE_CENTER_NAME", "SSL_CERT", ""] {
            assert!(!is_steering(OsStr::new(n)), "{n}");
        }
    }

    /// Prints the steering variables left after
    /// [`take_machine_environment`], for [`the_steering_variables_come_from_the_machine`].
    #[cfg(windows)]
    #[test]
    #[ignore = "run by the_steering_variables_come_from_the_machine, in a process of its own"]
    fn print_the_steering_variables() {
        // SAFETY: a process of its own, run with `--test-threads=1`, that
        // reads these variables nowhere else.
        unsafe { take_machine_environment() };
        let left: Vec<_> = std::env::vars_os()
            .filter(|(k, _)| is_steering(k))
            .collect();
        println!("steering: {left:?}");
    }

    /// An elevated terminal's variables of the account (`HTTPS_PROXY`, the
    /// trusted certificates) do not reach the administrator's commands
    /// (round 7, security 2). Set for a process of its own.
    #[cfg(windows)]
    #[test]
    fn the_steering_variables_come_from_the_machine() {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            "win::folders::tests::print_the_steering_variables",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        for k in STEERING {
            c.env(k, "decoy-from-the-account");
        }
        let o = c.output().unwrap();
        let said = String::from_utf8_lossy(&o.stdout);
        assert!(o.status.success(), "{said}");
        assert!(said.contains("steering: ["), "{said}");
        assert!(!said.contains("decoy-from-the-account"), "{said}");
    }

    /// The machine's folders as this process finds them, for
    /// [`the_machine_folders_are_not_the_variables`].
    #[cfg(windows)]
    #[test]
    #[ignore = "run by the_machine_folders_are_not_the_variables, in a process of its own"]
    fn print_the_machine_folders() {
        println!(
            "folders: {:?}",
            (windows_dir(), system32(), program_data(), program_files())
        );
    }

    /// The folders stay the system's whatever the variables of the process
    /// say, as an elevated terminal takes them from the account's own
    /// (round 6, security 1). The variables are set for a process of its
    /// own, since other tests here read them.
    #[cfg(windows)]
    #[test]
    fn the_machine_folders_are_not_the_variables() {
        let here = (windows_dir(), system32(), program_data(), program_files());
        for f in [&here.0, &here.1, &here.2, &here.3] {
            assert!(f.is_absolute() && f.is_dir(), "{f:?}");
        }
        assert!(here.1.starts_with(&here.0), "{here:?}");
        let decoy = tempfile::tempdir().unwrap();
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            "win::folders::tests::print_the_machine_folders",
            "--ignored",
            "--nocapture",
        ]);
        for k in [
            "SystemRoot",
            "windir",
            "ProgramData",
            "ProgramFiles",
            "SystemDrive",
        ] {
            c.env(k, decoy.path());
        }
        let o = c.output().unwrap();
        let said = String::from_utf8_lossy(&o.stdout);
        assert!(o.status.success(), "{said}");
        assert!(said.contains(&format!("folders: {here:?}")), "{said}");
    }
}
