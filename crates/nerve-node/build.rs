//! Links the message table of the node's Windows Event Log entries
//! (nerve-service/src/eventlog.rs) into the program, so the Event Viewer
//! shows their text.
//! Windows' linker takes a `.res` file as it takes an object; the GNU one
//! does not, so a windows-gnu build goes without it.
//!
//! Windows looks for a DLL in the program's own folder before System32,
//! except for its KnownDLLs. The downloaded program runs from the
//! downloads, and as administrator when it installs, so a DLL put beside it
//! would run with those rights. The DLLs it takes that are not KnownDLLs
//! load on first use instead, after main told Windows to look in System32
//! only (tests/dlls.rs checks that no other is loaded at start).

#[allow(dead_code)]
#[path = "../nerve-service/src/eventlog.rs"]
mod eventlog;

/// The DLLs the Windows program imports that are not among Windows'
/// KnownDLLs (`HKLM\SYSTEM\CurrentControlSet\Control\Session
/// Manager\KnownDLLs`), as `llvm-readobj --coff-imports` lists them.
const DELAYED: [&str; 5] = [
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "crypt32.dll",
    "netapi32.dll",
    "userenv.dll",
];

fn main() {
    println!("cargo:rerun-if-changed=../nerve-service/src/eventlog.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let res = out.join("eventlog.res");
    std::fs::write(&res, eventlog::resource()).expect("write eventlog.res");
    // Every program of the crate, its tests included, carries the table.
    println!("cargo:rustc-link-arg={}", res.display());
    for dll in DELAYED {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
    }
    println!("cargo:rustc-link-arg-bins=delayimp.lib");
    // The bin's test harness imports none of them, and the linker would
    // say so for each (LNK4199).
    println!("cargo:rustc-link-arg-bins=/IGNORE:4199");
}
