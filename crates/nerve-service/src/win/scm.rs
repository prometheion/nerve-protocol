//! A handle of the Windows service control manager or of one service.

use windows_sys::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, GetLastError};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_STATUS_PROCESS_INFO, SERVICE_STATUS_PROCESS,
};

use crate::win::sid::wide;

fn last() -> String {
    std::io::Error::last_os_error().to_string()
}

/// A handle of the service control manager, or of a service, closed when
/// dropped.
pub struct Scm(pub SC_HANDLE, pub String);

impl Drop for Scm {
    fn drop(&mut self) {
        // SAFETY: a handle from OpenSCManagerW or OpenServiceW, closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

impl Scm {
    pub fn open(access: u32) -> Result<Scm, String> {
        // SAFETY: this machine's active database.
        let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
        if h.is_null() {
            return Err(format!(
                "cannot open the service control manager: {}",
                last()
            ));
        }
        Ok(Scm(h, String::new()))
    }

    /// The service `name`; `None` when it is not registered.
    pub fn service(&self, name: &str, access: u32) -> Result<Option<Scm>, String> {
        // SAFETY: an open manager and a NUL-terminated name.
        let h = unsafe { OpenServiceW(self.0, wide(name).as_ptr(), access) };
        if h.is_null() {
            // SAFETY: plain getter, right after the call.
            if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(None);
            }
            return Err(format!("cannot open the service {name}: {}", last()));
        }
        Ok(Some(Scm(h, name.into())))
    }

    /// The service's state and process.
    pub fn status(&self) -> Result<SERVICE_STATUS_PROCESS, String> {
        // SAFETY: plain data that the call fills.
        let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut need = 0;
        // SAFETY: a buffer of the size given.
        let ok = unsafe {
            QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                (&raw mut st).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut need,
            )
        };
        if ok == 0 {
            return Err(format!("cannot ask the service {}: {}", self.1, last()));
        }
        Ok(st)
    }
}
