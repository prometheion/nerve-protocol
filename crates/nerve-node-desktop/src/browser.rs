//! Opens the node's web UI in the person's browser, once the app has checked
//! that the node's service holds its port (nerve_node::cli::ui::holder): the
//! desktop's own opener on Linux (`xdg-open`), the shell's on Windows.

/// Opens `url` (an `http` or `https` one) in the default browser.
pub fn open(url: &str) -> Result<(), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("{url:?} is no web address"));
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
        let (verb, target) = (wide("open"), wide(url));
        // SAFETY: NUL-terminated strings that live through the call.
        let r = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // A value of 32 or less is an error.
        if r as usize <= 32 {
            return Err(format!("Windows could not open {url}"));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            // Waited for, so it leaves no process behind once it ends.
            .map(|mut child| {
                std::thread::spawn(move || child.wait());
            })
            .map_err(|e| format!("cannot open {url}: xdg-open: {e}"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_web_address_is_opened() {
        assert!(super::open("file:///etc/passwd").is_err());
        assert!(super::open("javascript:alert(1)").is_err());
    }
}
