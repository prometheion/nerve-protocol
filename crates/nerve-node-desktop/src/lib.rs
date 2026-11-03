//! The node's desktop app: a window that drives `nerve-node`. Every action
//! runs the CLI (the same program, [`runner`]) and shows its JSON answer
//! ([`view`]), so the app has the CLI's checks and audit records and keeps
//! no settings of its own.

slint::include_modules!();

pub mod app;
pub mod broker;
pub mod deps;
pub mod dialog;
pub mod headless;
pub mod in_app;
pub mod instance;
pub mod motion;
pub mod parts;
pub mod reference;
pub mod runner;
pub mod scheme;
pub mod settings;
pub mod view;
