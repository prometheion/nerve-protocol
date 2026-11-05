//! A machine in a temporary folder, for the tests of the node's and the
//! center's services: the service's user is the test's own account, every
//! other account another uid, and systemctl, the folders given away and the
//! service's starts are recorded. A program here is a text file: its first
//! line is what its `--version` says, the rest what `service-files` says
//! (an empty object when there is no rest).

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use crate::{Account, System, chown_tree};

pub struct Fake {
    /// The service's user and its mark.
    pub name: &'static str,
    pub mark: &'static str,
    pub home: &'static str,
    pub user: RefCell<Option<Account>>,
    /// The other accounts of the machine.
    pub others: RefCell<Vec<Account>>,
    pub calls: RefCell<Vec<String>>,
    /// The folders given to another user, and to whom.
    pub given: RefCell<Vec<(PathBuf, u32)>>,
    /// Whether a service started answers.
    pub starts: Cell<bool>,
    /// Whether the next start answers, before `starts` holds again: the
    /// old program that goes back starts where the new one did not.
    pub next_start: Cell<Option<bool>>,
    /// Whether the command runs as root.
    pub root: Cell<bool>,
    /// What each run of a program was asked, its arguments after the path.
    pub runs: RefCell<Vec<String>>,
}

impl Fake {
    /// A machine without the service's user `name` yet, marked `mark` with
    /// the home `home` once `add_account` makes it.
    pub fn new(name: &'static str, mark: &'static str, home: &'static str) -> Fake {
        Fake {
            name,
            mark,
            home,
            user: RefCell::new(None),
            others: RefCell::new(Vec::new()),
            calls: RefCell::new(Vec::new()),
            given: RefCell::new(Vec::new()),
            starts: Cell::new(true),
            next_start: Cell::new(None),
            root: Cell::new(true),
            runs: RefCell::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// The service's user: the test's own account.
    pub fn me(&self) -> Account {
        // SAFETY: plain getters.
        #[cfg(unix)]
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        #[cfg(not(unix))]
        let (uid, gid) = (1000, 1000);
        Account {
            name: self.name.into(),
            uid,
            gid,
            comment: self.mark.into(),
            home: self.home.into(),
            groups: vec![gid],
        }
    }

    /// Whether the service the last start started answers.
    pub fn started(&self) -> Result<(), String> {
        if self.next_start.take().unwrap_or(self.starts.get()) {
            Ok(())
        } else {
            Err("the service does not answer".into())
        }
    }
}

/// An account that is not the test's own.
pub fn other(name: &str, uid: u32) -> Account {
    Account {
        name: name.into(),
        uid,
        gid: uid,
        comment: String::new(),
        home: format!("/home/{name}").into(),
        groups: vec![uid],
    }
}

impl System for Fake {
    fn is_root(&self) -> bool {
        self.root.get()
    }
    fn has_systemd(&self) -> bool {
        true
    }
    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        if name == self.name {
            return Ok(self.user.borrow().clone());
        }
        Ok(self
            .others
            .borrow()
            .iter()
            .find(|a| a.name == name)
            .cloned())
    }
    /// The service's user is the test's own account; any other is another
    /// uid.
    fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String> {
        self.calls
            .borrow_mut()
            .push(format!("useradd {name} {}", home.display()));
        if name == self.name {
            *self.user.borrow_mut() = Some(self.me());
        } else {
            let uid = 5000 + self.others.borrow().len() as u32;
            self.others.borrow_mut().push(Account {
                comment: mark.into(),
                home: home.into(),
                ..other(name, uid)
            });
        }
        Ok(())
    }
    fn remove_account(&self, name: &str) -> Result<(), String> {
        self.calls.borrow_mut().push(format!("userdel {name}"));
        if name == self.name {
            *self.user.borrow_mut() = None;
        } else {
            self.others.borrow_mut().retain(|a| a.name != name);
        }
        Ok(())
    }
    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        self.calls
            .borrow_mut()
            .push(format!("systemctl {}", args.join(" ")));
        Ok(())
    }
    /// The test may give files to itself only; giving them to anyone else
    /// is recorded.
    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        if uid == self.me().uid {
            chown_tree(path, uid, gid)
        } else {
            self.given.borrow_mut().push((path.to_path_buf(), uid));
            Ok(())
        }
    }
    fn output_of(
        &self,
        program: &Path,
        account: &Account,
        args: &[&str],
    ) -> Result<String, String> {
        assert_eq!(account.comment, self.mark, "run as the service's user");
        self.runs.borrow_mut().push(args.join(" "));
        let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
        let (first, rest) = text.split_once('\n').unwrap_or((&text, ""));
        match args.first().copied() {
            Some("--version") => Ok(first.to_string()),
            Some("service-files") if rest.trim().is_empty() => Ok("{}".into()),
            Some("service-files") => Ok(rest.trim().to_string()),
            _ => Err(format!("{}: unknown arguments {args:?}", program.display())),
        }
    }
}
