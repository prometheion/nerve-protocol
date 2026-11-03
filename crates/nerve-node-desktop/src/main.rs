//! `nerve-node-desktop`: the node with its desktop app, in one program. Started
//! with arguments it is `nerve-node`, which the app runs for every action;
//! started without any it opens the window.

// No console window behind the app on Windows. Started with arguments it is
// the app's interface to the node (src/runner.rs, src/broker.rs), which
// reads its pipes, and not a command line for a person: it takes no
// terminal's console, and on Windows the app is the only way to the node.
#![cfg_attr(windows, windows_subsystem = "windows")]

use nerve_node_desktop::instance::Asked;

fn main() {
    // DLLs from System32 only, never from the program's own folder, which
    // is the downloads before the program is installed (build.rs delays
    // the DLLs that would load before this line). Every supported Windows
    // can; one that cannot gets no further.
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::{
            LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
        };
        // SAFETY: a flag for this process's DLL search.
        if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
            std::process::exit(1);
        }
    }
    // This program is the desktop app's edition of the node: installed as
    // nerve-node-desktop, with its menu entry and link handler.
    nerve_node::edition::set(&nerve_node_desktop::parts::EDITION);
    // Not `args()`: a path for the CLI need not be UTF-8.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    // The elevated broker of the app (nerve_node_desktop::broker), started by
    // the app itself.
    if words.first() == Some(&Some(nerve_node_desktop::broker::ARG)) {
        let rest: Vec<String> = args[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(nerve_node_desktop::broker::main(&rest));
    }
    // One file dialog of the app's (nerve_node_desktop::dialog).
    if words.first() == Some(&Some(nerve_node_desktop::dialog::ARG)) {
        let rest: Vec<String> = args[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(nerve_node_desktop::dialog::main(&rest));
    }
    // A nerve:// link alone, which the desktop hands to the app when one is
    // opened (no command of nerve-node): the app goes straight to pairing.
    // The uninstall of Apps & features on Windows opens the app's.
    let start = match words.as_slice() {
        [Some(link)] if link.to_ascii_lowercase().starts_with("nerve://") => {
            Some(Asked::link(link))
        }
        [Some(arg)] if *arg == nerve_node_desktop::parts::UNINSTALL_ARG => Some(Asked {
            uninstall: true,
            ..Asked::default()
        }),
        [] => Some(Asked::default()),
        _ => None,
    };
    let Some(start) = start else {
        std::process::exit(nerve_node::entry::main());
    };
    use nerve_node_desktop::app::Failed;
    use nerve_node_desktop::deps;
    let fail = |e: &str| -> ! {
        eprintln!("nerve-node-desktop: {e}");
        // Started from the menu, nobody reads stderr.
        deps::notify("Nerve cannot open its window", e);
        std::process::exit(1);
    };
    // Windows' pixel format calls answer only once opengl32 is loaded, and
    // Slint asks them whether OpenGL 2 is there before it draws with it
    // (in software otherwise); opengl32 is delayed (build.rs), so it is
    // loaded here, from System32.
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::{
            LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
        };
        let name: Vec<u16> = "opengl32.dll".encode_utf16().chain(Some(0)).collect();
        // SAFETY: a library of the system, kept for the program's life.
        unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
    }
    match nerve_node_desktop::app::run(start) {
        Ok(()) => {}
        Err(Failed::NoDisplay(e)) => fail(&e),
        Err(Failed::Window(e)) => {
            let chosen = std::env::var(deps::BACKEND_VAR).ok();
            match deps::after_window_error(&e, chosen.as_deref()) {
                deps::Next::Software => {
                    eprintln!(
                        "nerve-node-desktop: the window did not open ({e}); trying once more, drawing in software without OpenGL"
                    );
                    std::process::exit(deps::rerun_in_software());
                }
                deps::Next::Fail(e) => fail(&e),
            }
        }
        Err(Failed::Other(e)) => {
            eprintln!("nerve-node-desktop: {e}");
            std::process::exit(1);
        }
    }
}
