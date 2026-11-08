//! Entries in the Windows Event Log, and the registration of their source.

use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RegDeleteKeyW, RegSetKeyValueW,
};

use crate::win::sid::wide;

fn os(code: u32) -> String {
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// Writes an entry to the Windows Event Log (Application) as the source
/// `source`, with the event id `id`, as an error or as information. Every
/// user of the machine may read that log, so the text is made one line,
/// redacted and cut as a line of the node's log is.
pub fn report(source: &str, id: u32, error: bool, text: &str) -> Result<(), String> {
    let text = nerve_transport::log::scrub(text);
    let source = wide(source);
    // SAFETY: this machine and a NUL-terminated name; a source that is not
    // registered still writes, to the Application log.
    let h = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if h.is_null() {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let line = wide(&text);
    let strings = [line.as_ptr()];
    let kind = if error {
        EVENTLOG_ERROR_TYPE
    } else {
        EVENTLOG_INFORMATION_TYPE
    };
    // SAFETY: an open source, one NUL-terminated string and no data.
    let ok = unsafe {
        ReportEventW(
            h,
            kind,
            0,
            id,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: the handle from above, closed once.
    unsafe { DeregisterEventSource(h) };
    if ok == 0 {
        return Err(err.to_string());
    }
    Ok(())
}

/// Registers `source` in the Application log below `key` (in
/// `HKEY_LOCAL_MACHINE`), with `bin`, the program that carries the message
/// table ([`crate::eventlog`]), as its message file.
pub fn put_source(key: &str, source: &str, bin: &Path) -> Result<(), String> {
    let file = wide(bin);
    // The node writes errors and information, nothing else.
    let types = u32::from(EVENTLOG_ERROR_TYPE | EVENTLOG_INFORMATION_TYPE);
    for (name, kind, data, len) in [
        (
            "EventMessageFile",
            REG_SZ,
            file.as_ptr().cast(),
            (file.len() * 2) as u32,
        ),
        ("TypesSupported", REG_DWORD, (&raw const types).cast(), 4),
    ] {
        // SAFETY: NUL-terminated key and value names; data of the length
        // given (the path with its NUL, or a DWORD). The key is made when
        // it is missing.
        let r = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                wide(key).as_ptr(),
                wide(name).as_ptr(),
                kind,
                data,
                len,
            )
        };
        if r != 0 {
            return Err(format!(
                "cannot register the source {source} in the Windows Event Log: {}",
                os(r)
            ));
        }
    }
    Ok(())
}

/// Removes the source `source` registered below `key`; whether it was
/// there.
pub fn delete_source(key: &str, source: &str) -> Result<bool, String> {
    // SAFETY: a NUL-terminated key name; the key has values only.
    match unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, wide(key).as_ptr()) } {
        0 => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        r => Err(format!(
            "cannot remove the source {source} from the Windows Event Log: {}",
            os(r)
        )),
    }
}
