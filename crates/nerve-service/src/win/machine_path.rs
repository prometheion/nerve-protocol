//! The machine's `Path` (the system environment variable), where the
//! center's install puts the folder of its program, as Linux has
//! `/usr/local/bin`: a terminal opened after the install finds
//! `nerve-center` by name, and a harness can start it so.

/// `path` with `dir` added at its end, or `None` when it holds `dir`
/// already. Entries compare without case and a trailing backslash, as
/// Windows finds a program by them.
pub fn with_dir(path: &str, dir: &str) -> Option<String> {
    if path.split(';').any(|e| same(e, dir)) {
        return None;
    }
    let path = path.trim_end_matches(';');
    Some(if path.is_empty() {
        dir.to_string()
    } else {
        format!("{path};{dir}")
    })
}

/// `path` without `dir`, or `None` when it does not hold it.
pub fn without_dir(path: &str, dir: &str) -> Option<String> {
    let entries: Vec<&str> = path.split(';').collect();
    if !entries.iter().any(|e| same(e, dir)) {
        return None;
    }
    Some(
        entries
            .into_iter()
            .filter(|e| !same(e, dir))
            .collect::<Vec<_>>()
            .join(";"),
    )
}

fn same(entry: &str, dir: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('\\').to_lowercase();
    !entry.trim().is_empty() && norm(entry) == norm(dir)
}

#[cfg(windows)]
mod system {
    use std::path::Path;

    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
        RegGetValueW, RegSetKeyValueW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };

    use crate::win::sid::wide;

    /// Where Windows keeps the machine's environment.
    const KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    fn os(code: u32) -> String {
        std::io::Error::from_raw_os_error(code as i32).to_string()
    }

    /// Puts `dir` at the end of the machine's `Path`; whether it was not
    /// there before.
    pub fn add(dir: &Path) -> Result<bool, String> {
        let dir = dir.display().to_string();
        match super::with_dir(&read()?, &dir) {
            Some(path) => write(&path).map(|()| true),
            None => Ok(false),
        }
    }

    /// Takes `dir` off the machine's `Path`; whether it was there.
    pub fn remove(dir: &Path) -> Result<bool, String> {
        let dir = dir.display().to_string();
        match super::without_dir(&read()?, &dir) {
            Some(path) => write(&path).map(|()| true),
            None => Ok(false),
        }
    }

    /// The machine's `Path` as it is stored, its `%…%` names kept.
    fn read() -> Result<String, String> {
        let (key, name) = (wide(KEY), wide("Path"));
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
        let mut len = 0u32;
        // SAFETY: NUL-terminated names; no buffer, to learn the length.
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(format!("cannot read the machine's Path: {}", os(r)));
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: as above, with a buffer of `len` bytes.
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(format!("cannot read the machine's Path: {}", os(r)));
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Ok(String::from_utf16_lossy(&buf[..end]))
    }

    /// Stores `path` as the machine's `Path` (with its `%…%` names, as
    /// Windows keeps it), and tells the open programs, so that a terminal
    /// opened after it has it.
    fn write(path: &str) -> Result<(), String> {
        let value = wide(path);
        // SAFETY: NUL-terminated names and the value with its NUL.
        let r = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                wide(KEY).as_ptr(),
                wide("Path").as_ptr(),
                REG_EXPAND_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        };
        if r != 0 {
            return Err(format!("cannot change the machine's Path: {}", os(r)));
        }
        let what = wide("Environment");
        let mut answer = 0usize;
        // SAFETY: a NUL-terminated string that lives through the call; a
        // window that does not answer within 5 s is skipped.
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                what.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                5000,
                &mut answer,
            )
        };
        Ok(())
    }
}

#[cfg(windows)]
pub use system::{add, remove};

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = r"C:\Program Files\Nerve";

    #[test]
    fn a_folder_goes_on_the_path_once() {
        assert_eq!(
            with_dir(r"%SystemRoot%\system32;C:\Tools", DIR).as_deref(),
            Some(r"%SystemRoot%\system32;C:\Tools;C:\Program Files\Nerve")
        );
        // A trailing separator is not doubled; an empty Path takes it alone.
        assert_eq!(
            with_dir(r"C:\Tools;", DIR).as_deref(),
            Some(r"C:\Tools;C:\Program Files\Nerve")
        );
        assert_eq!(with_dir("", DIR).as_deref(), Some(DIR));
        // There already, in another case or with a trailing backslash.
        assert_eq!(with_dir(r"c:\program files\nerve\;C:\Tools", DIR), None);
    }

    #[test]
    fn a_folder_comes_off_the_path_and_nothing_else() {
        assert_eq!(
            without_dir(
                r"%SystemRoot%\system32;C:\Program Files\Nerve\;C:\Tools",
                DIR
            )
            .as_deref(),
            Some(r"%SystemRoot%\system32;C:\Tools")
        );
        assert_eq!(
            without_dir(r"C:\Program Files\Nerve Other;C:\Tools", DIR),
            None
        );
        // An empty entry is no match for anything.
        assert_eq!(without_dir(";C:\\Tools", DIR), None);
    }
}
