//! Compiles the app's Slint files (ui/) into Rust, with the fluent style for
//! the few std widgets it takes (the scroll bars, AboutSlint): the app draws
//! its own controls.
//!
//! On Windows the program also carries its icon, which Explorer, the Start
//! menu entry and the link handler show, and the node's message table of
//! the Event Log (nerve-node's build.rs does that for nerve-node.exe only):
//! the installed service runs this program, which is the Event Log's message
//! file then. Both go in one `.res` file, which the linker takes as it takes
//! an object; the GNU linker does not, so a windows-gnu build goes without.

#[allow(dead_code)]
#[path = "../nerve-service/src/eventlog.rs"]
mod eventlog;

/// The DLLs the Windows program imports that are not among Windows'
/// KnownDLLs (`HKLM\SYSTEM\CurrentControlSet\Control\Session
/// Manager\KnownDLLs`), as `llvm-readobj --coff-imports` lists them.
const DELAYED: [&str; 11] = [
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "comctl32.dll",
    "crypt32.dll",
    "dwmapi.dll",
    "dwrite.dll",
    "netapi32.dll",
    "opengl32.dll",
    "uiautomationcore.dll",
    "userenv.dll",
    "uxtheme.dll",
];

fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("the Slint files compile");

    println!("cargo:rerun-if-changed=ui/icons/app.ico");
    println!("cargo:rerun-if-changed=../nerve-service/src/eventlog.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    // Windows looks for a DLL in the program's own folder before System32,
    // except for its KnownDLLs. The downloaded program runs from the
    // downloads, and elevated when it installs, so a DLL put beside it
    // would run as administrator. The DLLs it takes that are not KnownDLLs
    // load on first use instead, after main told Windows to look in System32
    // only (tests/dlls.rs checks that no other is loaded at start).
    for dll in DELAYED {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
    }
    println!("cargo:rustc-link-arg-bins=delayimp.lib");
    // The bin's test harness imports none of them, and the linker would
    // say so for each (LNK4199).
    println!("cargo:rustc-link-arg-bins=/IGNORE:4199");
    let mut res = eventlog::resource();
    icon(
        &mut res,
        &std::fs::read("ui/icons/app.ico").expect("ui/icons/app.ico"),
    );
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let path = out.join("desktop.res");
    std::fs::write(&path, res).expect("write desktop.res");
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

/// The images of an `.ico` file as resources: one `RT_ICON` each, and the
/// `RT_GROUP_ICON` that lists them, as rc.exe makes them. The group's entry
/// is the file's directory entry with the image's resource id in place of
/// its offset.
fn icon(res: &mut Vec<u8>, ico: &[u8]) {
    const RT_ICON: u16 = 3;
    const RT_GROUP_ICON: u16 = 14;
    let u16_at = |at: usize| u16::from_le_bytes([ico[at], ico[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes(ico[at..at + 4].try_into().unwrap());
    let count = u16_at(4);
    let mut group = ico[0..6].to_vec();
    for i in 0..count {
        let at = 6 + 16 * i as usize;
        let (len, offset) = (u32_at(at + 8) as usize, u32_at(at + 12) as usize);
        eventlog::entry(res, RT_ICON, i + 1, 0, &ico[offset..offset + len]);
        group.extend_from_slice(&ico[at..at + 12]);
        group.extend_from_slice(&(i + 1).to_le_bytes());
    }
    eventlog::entry(res, RT_GROUP_ICON, 1, 0, &group);
}
