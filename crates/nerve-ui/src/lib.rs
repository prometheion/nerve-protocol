//! The desktop app's window, pages and dialogs, as Slint compiles them from
//! crates/nerve/ui. A crate of its own so that cargo compiles the generated
//! code once, as a dependency: in the app's crate every test build compiled
//! it again, and one such rustc takes about 9 GB. The app re-exports
//! all of it (`nerve::AppWindow` and the rest).

slint::include_modules!();
