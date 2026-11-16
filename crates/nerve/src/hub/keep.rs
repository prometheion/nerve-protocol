//! The center's owner token for the next start of the app, where its owner
//! chose so (Settings, Owner token, "Remember the log-in in my keyring";
//! owner decision on #232). Off by default: the token stays in the app's
//! memory until it closes and is asked for at the next start. On: it is in
//! the user's keyring, which every program of the user may read, a
//! harness's agent among them; the switch says so.

use std::sync::{Arc, Mutex};

/// The keyring entry's service and account.
pub const SERVICE: &str = "nerve-app";
pub const ACCOUNT: &str = "center-owner-token";

/// Where a kept log-in lives; tests answer for it.
pub trait Keyring: Send + Sync {
    fn get(&self) -> Result<Option<String>, String>;
    fn set(&self, token: &str) -> Result<(), String>;
    /// Forgets it; nothing kept is no error.
    fn delete(&self) -> Result<(), String>;
}

/// The user's keyring: Credential Manager on Windows, the Secret Service on
/// Linux.
pub struct System;

impl Keyring for System {
    fn get(&self) -> Result<Option<String>, String> {
        nerve_node::user_keyring::get(SERVICE, ACCOUNT)
    }

    fn set(&self, token: &str) -> Result<(), String> {
        nerve_node::user_keyring::set(SERVICE, ACCOUNT, token)
    }

    fn delete(&self) -> Result<(), String> {
        nerve_node::user_keyring::delete(SERVICE, ACCOUNT).map(|_| ())
    }
}

/// A keyring in memory, for tests.
#[derive(Default)]
pub struct Memory(pub Mutex<Option<String>>);

impl Keyring for Memory {
    fn get(&self) -> Result<Option<String>, String> {
        Ok(self.0.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    fn set(&self, token: &str) -> Result<(), String> {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(token.to_string());
        Ok(())
    }

    fn delete(&self) -> Result<(), String> {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = None;
        Ok(())
    }
}

/// The app's keyring: the system's, or one a test gives.
pub type Shared = Arc<dyn Keyring>;

/// The switch turned on or off: on keeps `token` (the one the app logged
/// in with, if any), off forgets what was kept.
pub fn switch(keyring: &dyn Keyring, on: bool, token: Option<&str>) -> Result<(), String> {
    match (on, token) {
        (true, Some(t)) => keyring.set(t),
        (true, None) => Ok(()),
        (false, _) => keyring.delete(),
    }
}

/// After a log-in with `token`: kept where the switch is on. A token that
/// failed is never kept, so the caller calls this only after a log-in that
/// worked.
pub fn after_login(keyring: &dyn Keyring, on: bool, token: &str) -> Result<(), String> {
    if on { keyring.set(token) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_switch_that_is_on_keeps_the_token() {
        let k = Memory::default();
        after_login(&k, false, "nrv_owner_a").unwrap();
        assert_eq!(k.get().unwrap(), None);
        after_login(&k, true, "nrv_owner_a").unwrap();
        assert_eq!(k.get().unwrap().as_deref(), Some("nrv_owner_a"));
        // Off forgets it at once.
        switch(&k, false, Some("nrv_owner_a")).unwrap();
        assert_eq!(k.get().unwrap(), None);
        // On keeps the one the app holds.
        switch(&k, true, Some("nrv_owner_b")).unwrap();
        assert_eq!(k.get().unwrap().as_deref(), Some("nrv_owner_b"));
    }
}
