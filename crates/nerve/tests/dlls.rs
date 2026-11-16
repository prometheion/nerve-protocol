//! The Windows program loads no DLL from its own folder: the downloaded
//! program runs from the downloads, elevated when it installs, so a DLL
//! put beside it would run as administrator (review issue-10 r1). At start
//! it takes only KnownDLLs, which Windows loads from System32 alone; the
//! others are delayed (build.rs) until main told Windows to look in
//! System32 only.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

fn u16_at(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn u32_at(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}

/// The names of the DLLs a PE32+ image imports, lower case: at start
/// (`delayed` false) or on first use.
fn imports(pe: &[u8], delayed: bool) -> Vec<String> {
    let nt = u32_at(pe, 0x3c);
    assert_eq!(&pe[nt..nt + 4], b"PE\0\0");
    let sections = u16_at(pe, nt + 6);
    let opt = nt + 24;
    assert_eq!(u16_at(pe, opt), 0x20b, "PE32+");
    let table = opt + u16_at(pe, nt + 20);
    let at = |rva: usize| {
        (0..sections)
            .map(|i| table + 40 * i)
            .find_map(|s| {
                let (size, va, raw) = (
                    u32_at(pe, s + 8).max(u32_at(pe, s + 16)),
                    u32_at(pe, s + 12),
                    u32_at(pe, s + 20),
                );
                (va <= rva && rva < va + size).then(|| rva - va + raw)
            })
            .expect("an address in a section")
    };
    // The import table is directory 1, the delayed one 13; their entries
    // are 20 and 32 bytes, with the name's address at 12 and 4.
    let (dir, entry, name) = if delayed { (13, 32, 4) } else { (1, 20, 12) };
    let rva = u32_at(pe, opt + 112 + 8 * dir);
    if rva == 0 {
        return Vec::new();
    }
    let mut dlls = Vec::new();
    let mut e = at(rva);
    while pe[e..e + entry].iter().any(|b| *b != 0) {
        let n = at(u32_at(pe, e + name));
        let len = pe[n..].iter().position(|b| *b == 0).unwrap();
        dlls.push(String::from_utf8_lossy(&pe[n..n + len]).to_ascii_lowercase());
        e += entry;
    }
    dlls
}

/// This machine's KnownDLLs, lower case.
fn known_dlls() -> Vec<String> {
    let o = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        ])
        .output()
        .unwrap();
    assert!(o.status.success());
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter(|v| v.to_ascii_lowercase().ends_with(".dll"))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Loaded from System32 whatever the search: ntdll, which Windows maps
/// before anything else, and the API sets, which are no files.
fn system_alone(dll: &str) -> bool {
    dll == "ntdll.dll" || dll.starts_with("api-ms-win-") || dll.starts_with("ext-ms-win-")
}

/// The program: the one Cargo built for this test, or the one
/// `NERVE_DESKTOP_EXE` names, such as a release build.
fn program() -> PathBuf {
    std::env::var_os("NERVE_DESKTOP_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_nerve")))
}

#[test]
fn the_program_takes_only_known_dlls_at_start() {
    let pe = std::fs::read(program()).unwrap();
    let known = known_dlls();
    let at_start: Vec<String> = imports(&pe, false)
        .into_iter()
        .filter(|d| !known.contains(d) && !system_alone(d))
        // The C runtime of a build without +crt-static, as a test's is;
        // the release's is static (.github/workflows/release.yml).
        .filter(|d| cfg!(target_feature = "crt-static") || d != "vcruntime140.dll")
        .collect();
    assert!(
        at_start.is_empty(),
        "loaded at start from the program's folder first: {at_start:?}; delay them in build.rs"
    );
    assert!(imports(&pe, true).contains(&"dwmapi.dll".to_string()));
}

#[test]
fn a_dll_beside_the_program_is_not_loaded() {
    let pe = std::fs::read(program()).unwrap();
    let known = known_dlls();
    let d = tempfile::tempdir().unwrap();
    let exe = d.path().join("nerve.exe");
    std::fs::copy(program(), &exe).unwrap();
    // No DLL at all, so Windows refuses to load one it finds here.
    let planted: Vec<String> = imports(&pe, false)
        .into_iter()
        .chain(imports(&pe, true))
        .filter(|d| !known.contains(d) && !system_alone(d) && d != "vcruntime140.dll")
        .collect();
    for dll in &planted {
        std::fs::write(d.path().join(dll), b"not a DLL").unwrap();
    }
    let said = |args: &[&str]| {
        let o = Command::new(&exe).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "{args:?} ended with {:?} beside {planted:?}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    assert_eq!(
        said(&["--version"]).trim(),
        format!("nerve {}", env!("CARGO_PKG_VERSION"))
    );
}
