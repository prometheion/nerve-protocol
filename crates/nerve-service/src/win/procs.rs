//! The system's list of processes as `NtQuerySystemInformation` writes it
//! (`SystemProcessInformation`): a chain of entries, each with the process
//! id and the session of one process. Any caller may read it, a service that
//! runs as no administrator too, which cannot open another account's
//! process to ask it ([`super::process`]). Only the layout is here, so it is
//! tested on every platform; a Windows test holds the offsets to the real
//! structure.

/// Where an entry keeps its process id, a pointer-sized number.
pub const ID_OFFSET: usize = if size_of::<usize>() == 8 { 80 } else { 68 };
/// Where it keeps the session, a `u32`.
pub const SESSION_OFFSET: usize = if size_of::<usize>() == 8 { 100 } else { 80 };

/// The session of the process `pid` in `list`, or `None` when it is not
/// there or the list is cut short.
pub fn session_in(list: &[u8], pid: u32) -> Option<u32> {
    let mut at = 0usize;
    loop {
        let entry = list.get(at..)?;
        let next = u32::from_ne_bytes(entry.get(..4)?.try_into().ok()?) as usize;
        let id = entry.get(ID_OFFSET..ID_OFFSET + size_of::<usize>())?;
        let id = match size_of::<usize>() {
            8 => u64::from_ne_bytes(id.try_into().ok()?),
            _ => u64::from(u32::from_ne_bytes(id.try_into().ok()?)),
        };
        if id == u64::from(pid) {
            let session = entry.get(SESSION_OFFSET..SESSION_OFFSET + 4)?;
            return Some(u32::from_ne_bytes(session.try_into().ok()?));
        }
        if next == 0 {
            return None;
        }
        at = at.checked_add(next)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry of the list: its size, process and session.
    fn entry(size: usize, pid: u32, session: u32, last: bool) -> Vec<u8> {
        let mut e = vec![0u8; size];
        let next = if last { 0 } else { size as u32 };
        e[..4].copy_from_slice(&next.to_ne_bytes());
        e[ID_OFFSET..ID_OFFSET + size_of::<usize>()].copy_from_slice(&(pid as usize).to_ne_bytes());
        e[SESSION_OFFSET..SESSION_OFFSET + 4].copy_from_slice(&session.to_ne_bytes());
        e
    }

    /// A process is found by its id wherever it stands in the chain, with
    /// its own session; one that is not there, or a list cut short, names
    /// none (round 2, correctness 1: the session of another account's
    /// process comes from here).
    #[test]
    fn a_process_is_found_in_the_chain_with_its_session() {
        let list: Vec<u8> = [
            entry(184, 0, 0, false),
            entry(200, 4, 0, false),
            entry(232, 4100, 3, false),
            entry(184, 77, 1, true),
        ]
        .concat();
        assert_eq!(session_in(&list, 4100), Some(3));
        assert_eq!(session_in(&list, 77), Some(1));
        assert_eq!(session_in(&list, 4), Some(0));
        assert_eq!(session_in(&list, 5), None);
        assert_eq!(session_in(&list[..list.len() - 90], 77), None);
        assert_eq!(session_in(&[], 4), None);
        // A loop in the chain ends at the end of the buffer.
        let mut cut = entry(184, 1, 1, false);
        cut[..4].copy_from_slice(&0x7fff_ffffu32.to_ne_bytes());
        assert_eq!(session_in(&cut, 2), None);
    }
}
