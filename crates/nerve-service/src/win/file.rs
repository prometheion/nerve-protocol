//! The identity of a file: its volume and file index, which a rename keeps
//! and a new file of the same name does not have. Not its creation time:
//! NTFS gives a file made soon after another of the same name was renamed
//! away that one's creation time (name tunnelling), which is what a log's
//! rotation does.

use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

/// The volume serial number and the file index of `path`, `None` where it
/// cannot be opened.
pub fn id(path: &Path) -> Option<(u64, u64)> {
    let f = std::fs::File::open(path).ok()?;
    // SAFETY: an all-zero struct of plain numbers.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a valid handle that lives through the call, and a struct of
    // the right size.
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    Some((
        u64::from(info.dwVolumeSerialNumber),
        u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
    ))
}
