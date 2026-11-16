//! `nerve`: the node with its desktop app, in one program. Started
//! with arguments it is `nerve-node`, which the app runs for every action;
//! started without any it opens the window.

// No console window behind the app on Windows. Started with arguments it is
// the app's interface to the node (src/runner.rs, src/broker.rs), which
// reads its pipes, and not a command line for a person: it takes no
// terminal's console, and on Windows the app is the only way to the node.
#![cfg_attr(windows, windows_subsystem = "windows")]

use nerve::instance::Asked;

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
    // This program is the app's edition of the node: installed as nerve,
    // with its menu entry and link handler; and of the center, which it
    // runs behind its hidden word.
    nerve_node::edition::set(&nerve::parts::EDITION);
    nerve_center::edition::set(&nerve::parts::CENTER_EDITION);
    // Not `args()`: a path for the CLI need not be UTF-8.
    let argv0 = std::env::args_os().next();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    // The center's command line: behind the hidden word, or started by its
    // terminal name, a link to this program (Linux).
    match nerve::started_as(argv0.as_deref(), words.first().copied().flatten()) {
        nerve::StartedAs::Center { skip } => {
            let argv = std::iter::once(std::ffi::OsString::from(
                nerve_center::edition::TERMINAL_NAME,
            ))
            .chain(args.into_iter().skip(skip))
            .collect();
            std::process::exit(match nerve_center::entry::main(argv) {
                c if c == std::process::ExitCode::SUCCESS => 0,
                _ => 1,
            });
        }
        nerve::StartedAs::Node => std::process::exit(nerve_node::entry::main()),
        nerve::StartedAs::App => {}
    }
    // The elevated broker of the app (nerve::broker), started by
    // the app itself.
    if words.first() == Some(&Some(nerve::broker::ARG)) {
        let rest: Vec<String> = args[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(nerve::broker::main(&rest));
    }
    // One file dialog of the app's (nerve::dialog).
    if words.first() == Some(&Some(nerve::dialog::ARG)) {
        let rest: Vec<String> = args[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(nerve::dialog::main(&rest));
    }
    // The files of the app's package, for the release (#212).
    if words.first() == Some(&Some(nerve::parts::PACKAGE_ROOT_ARG)) {
        let rest: Vec<String> = args[1..]
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(nerve::parts::package_root_main(&rest));
    }
    // A silent install, for winget (#67): no window, no question.
    if words == [Some(nerve::parts::SILENT_ARG)] {
        std::process::exit(nerve::parts::silent_install());
    }
    // A nerve:// link alone, which the desktop hands to the app when one is
    // opened (no command of nerve-node): the app goes straight to pairing.
    // The link is taken off this command line at once: a new start gets it
    // on stdin, and this one ends (nerve::instance). The
    // uninstall of Apps & features on Windows opens the app's.
    use nerve::instance::{Start, hand_on, link_on_stdin};
    let start = match Start::of(&words, nerve::parts::UNINSTALL_ARG) {
        Start::Window(asked) => asked,
        Start::HandOn(link) => {
            let handed = std::env::current_exe().and_then(|me| hand_on(&me, &link, &[]));
            std::process::exit(match handed {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("nerve: cannot start the app for the link: {e}");
                    1
                }
            });
        }
        // A link that did not come is a start without one.
        Start::LinkOnStdin => link_on_stdin().map(|l| Asked::link(&l)).unwrap_or_default(),
        Start::Command => std::process::exit(nerve_node::entry::main()),
    };
    let link = start.link.clone();
    use nerve::app::Failed;
    use nerve::deps;
    let fail = |e: &str| -> ! {
        eprintln!("nerve: {e}");
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
    match nerve::app::run(start) {
        Ok(()) => {}
        Err(Failed::NoDisplay(e)) => fail(&e),
        Err(Failed::Window(e)) => {
            let chosen = std::env::var(deps::BACKEND_VAR).ok();
            match deps::after_window_error(&e, chosen.as_deref()) {
                deps::Next::Software => {
                    eprintln!(
                        "nerve: the window did not open ({e}); trying once more, drawing in software without OpenGL"
                    );
                    std::process::exit(deps::rerun_in_software(link.as_deref()));
                }
                deps::Next::Fail(e) => fail(&e),
            }
        }
        Err(Failed::Other(e)) => {
            eprintln!("nerve: {e}");
            std::process::exit(1);
        }
    }
}
