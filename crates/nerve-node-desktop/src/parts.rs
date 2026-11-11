//! What the desktop app installs besides the node, as `install`, `update`
//! and `uninstall` of this program do it (nerve_node::edition): the entry in
//! the application menu with the app's icon, and the handler of `nerve://`
//! links, both opening the installed program.
//!
//! - Linux: a desktop entry in `/usr/local/share/applications`, which GNOME
//!   and KDE read, its icon in the hicolor theme of `/usr/local/share/icons`,
//!   and `x-scheme-handler/nerve` in the entry and as the default in
//!   `/etc/xdg/mimeapps.list`. The app from a .deb or .rpm (#212) has the
//!   package's entry and icon in `/usr/share` ([`package_root`]), so it
//!   writes only the default handler.
//! - Windows: a shortcut in the Start menu of all users, the URL protocol
//!   `nerve` in `HKLM\Software\Classes`, and the entry in Apps & features
//!   (`HKLM\…\Uninstall\Nerve`), whose Uninstall opens the app's
//!   ([`UNINSTALL_ARG`]). The program carries its icon itself (build.rs).

use std::path::{Path, PathBuf};

use nerve_node::edition::{Edition, Parts};
pub use nerve_node::service::Package;

/// The program's name, and the id of its menu entry and icon.
pub const PROGRAM: &str = nerve_node::edition::DESKTOP_PROGRAM;

/// This program: the node with the desktop app.
pub static EDITION: Edition = Edition {
    program: PROGRAM,
    parts: Some(&Desktop),
};

/// The parts of this machine.
pub struct Desktop;

impl Parts for Desktop {
    fn install(&self, bin: &Path) -> Result<Vec<String>, String> {
        #[cfg(windows)]
        return win::install(bin);
        #[cfg(not(windows))]
        Places::system().install(bin)
    }

    fn uninstall(&self, bin: &Path) -> Result<Vec<String>, String> {
        #[cfg(windows)]
        return win::uninstall(bin);
        #[cfg(not(windows))]
        {
            let _ = bin;
            Places::system().uninstall()
        }
    }
}

/// The argument that opens the app on its uninstall: what Windows' Apps &
/// features runs. Not a command of `nerve-node`, so no command line takes
/// it for one.
pub const UNINSTALL_ARG: &str = "__desktop-uninstall";

/// The switch of a silent install (winget, #67): `install` without a
/// window and without a question; the app asks for the owner's password
/// later, where it is needed.
pub const SILENT_ARG: &str = "--silent";

/// What a silent install runs: the program's own `install`, the owner's
/// password not asked (no input), its output the caller's.
pub fn silent_install() -> i32 {
    let me = match std::env::current_exe() {
        Ok(me) => me,
        Err(e) => {
            eprintln!("nerve-node-desktop: {e}");
            return 1;
        }
    };
    match std::process::Command::new(me)
        .args(SILENT_COMMAND)
        .stdin(std::process::Stdio::null())
        .status()
    {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("nerve-node-desktop: {e}");
            1
        }
    }
}

/// The command a silent install runs.
pub const SILENT_COMMAND: [&str; 1] = ["install"];

/// The scheme of the links the app opens.
pub const SCHEME: &str = "nerve";
const MIME: &str = "x-scheme-handler/nerve";

/// Where the parts go on Linux: the system's folders, or a test's.
pub struct Places {
    /// The desktop entries.
    pub applications: PathBuf,
    /// The hicolor icon theme.
    pub icons: PathBuf,
    /// The system's default handlers.
    pub mimeapps: PathBuf,
    /// Whether to tell the desktop's caches.
    pub refresh: bool,
    /// The program that does: update-desktop-database.
    pub cache_tool: &'static str,
    /// Whether the app came from a package, which has the menu entry and
    /// the icon.
    pub packaged: bool,
}

impl Places {
    pub fn system() -> Places {
        Places {
            applications: "/usr/local/share/applications".into(),
            icons: "/usr/local/share/icons/hicolor".into(),
            mimeapps: "/etc/xdg/mimeapps.list".into(),
            refresh: true,
            cache_tool: "update-desktop-database",
            packaged: nerve_node::service::package_at(Path::new(Package::MARK)).is_some(),
        }
    }

    /// Below `root`, for the tests.
    pub fn under(root: &Path) -> Places {
        Places {
            applications: root.join("usr/local/share/applications"),
            icons: root.join("usr/local/share/icons/hicolor"),
            mimeapps: root.join("etc/xdg/mimeapps.list"),
            refresh: false,
            cache_tool: "update-desktop-database",
            packaged: false,
        }
    }

    pub fn entry(&self) -> PathBuf {
        self.applications.join(format!("{PROGRAM}.desktop"))
    }

    pub fn icon(&self) -> PathBuf {
        self.icons
            .join("scalable/apps")
            .join(format!("{PROGRAM}.svg"))
    }

    pub fn install(&self, bin: &Path) -> Result<Vec<String>, String> {
        let mut did = Vec::new();
        if self.packaged {
            // The package's entry is the menu's Nerve: an earlier plain
            // program's would show it twice.
            if self.remove_entry()? {
                did.push(
                    "removed the menu entry of the earlier program: the package has its own"
                        .to_string(),
                );
            }
        } else {
            write(&self.icon(), ICON, 0o644)?;
            write(&self.entry(), desktop_entry(bin).as_bytes(), 0o644)?;
            did.push(format!(
                "put Nerve in the application menu ({}), with its icon",
                self.entry().display()
            ));
        }
        let before = std::fs::read_to_string(&self.mimeapps).unwrap_or_default();
        write(
            &self.mimeapps,
            with_default(&before, MIME, &format!("{PROGRAM}.desktop")).as_bytes(),
            0o644,
        )?;
        did.push(format!(
            "nerve:// links open in Nerve (the default in {})",
            self.mimeapps.display()
        ));
        // Installed all the same: the desktop reads the entry at the next
        // login without the cache.
        if let Some(missing) = self.refresh() {
            did.push(format!(
                "Warning: {missing} is not on this machine, so the desktop may not know yet that Nerve opens nerve:// links. Install desktop-file-utils, or log out and in."
            ));
        }
        Ok(did)
    }

    /// Removes the menu entry and the icon [`Places::install`] wrote, and
    /// the icon's folders that hold nothing else; whether one was there.
    fn remove_entry(&self) -> Result<bool, String> {
        let mut gone = false;
        for p in [self.entry(), self.icon()] {
            match std::fs::remove_file(&p) {
                Ok(()) => gone = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", p.display())),
            }
        }
        // The icon's folders, when nothing else is in them, up to the
        // `icons` folder that install may have made.
        let top = self
            .icons
            .parent()
            .and_then(Path::parent)
            .unwrap_or(&self.icons)
            .to_path_buf();
        let mut dir = self.icon().parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d == top || std::fs::remove_dir(&d).is_err() {
                break;
            }
            dir = d.parent().map(Path::to_path_buf);
        }
        Ok(gone)
    }

    pub fn uninstall(&self) -> Result<Vec<String>, String> {
        let mut did = Vec::new();
        if self.remove_entry()? {
            did.push("removed Nerve from the application menu".to_string());
        }
        if let Ok(before) = std::fs::read_to_string(&self.mimeapps) {
            let after = without_default(&before, MIME, &format!("{PROGRAM}.desktop"));
            if after != before {
                // A file that held only this goes.
                if after
                    .lines()
                    .all(|l| l.trim().is_empty() || l.trim().starts_with('['))
                {
                    std::fs::remove_file(&self.mimeapps)
                        .map_err(|e| format!("{}: {e}", self.mimeapps.display()))?;
                } else {
                    write(&self.mimeapps, after.as_bytes(), 0o644)?;
                }
                did.push("nerve:// links no longer open in Nerve".to_string());
            }
        }
        if !did.is_empty() {
            let _ = self.refresh();
        }
        // The cache update-desktop-database left, when it names no other
        // program's entry, and the folder that held only Nerve's.
        let cache = self.applications.join("mimeinfo.cache");
        let only_cache = std::fs::read_dir(&self.applications)
            .is_ok_and(|d| d.flatten().all(|e| e.file_name() == "mimeinfo.cache"));
        if only_cache && std::fs::read_to_string(&cache).is_ok_and(|c| c.trim() == "[MIME Cache]") {
            let _ = std::fs::remove_file(&cache);
        }
        let _ = std::fs::remove_dir(&self.applications);
        Ok(did)
    }

    /// Tells the desktop about the change where its tools are there: the
    /// cache of which entry opens which links, and the icon theme's time,
    /// which GTK checks. The cache's tool when it is missing.
    fn refresh(&self) -> Option<&'static str> {
        if !self.refresh {
            return None;
        }
        let cached = std::process::Command::new(self.cache_tool)
            .arg("-q")
            .arg(&self.applications)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::process::Command::new("touch")
            .arg("--no-create")
            .arg(&self.icons)
            .status();
        cached
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            .then_some(self.cache_tool)
    }
}

/// The app's icon, which the menu shows.
pub const ICON: &[u8] = include_bytes!("../ui/icons/app.svg");

/// The hidden argument that writes the files of the app's package (#212):
/// `__package-root <folder> deb|rpm`, which the release packs with
/// dpkg-deb and rpmbuild (.github/scripts/desktop-packages.sh).
pub const PACKAGE_ROOT_ARG: &str = "__package-root";

/// The files of the app's package below `root`, with this program `exe`:
/// the program in `/usr/bin`, its menu entry and icon in `/usr/share`, and
/// the mark of the package's kind ([`Package::MARK`]); what it wrote.
pub fn package_root(root: &Path, exe: &Path, package: Package) -> Result<Vec<PathBuf>, String> {
    let under = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));
    let bin = Path::new("/usr/bin").join(PROGRAM);
    let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let share = Places {
        applications: under(Path::new("/usr/share/applications")),
        icons: under(Path::new("/usr/share/icons/hicolor")),
        ..Places::under(root)
    };
    let files = [
        (under(&bin), program, 0o755),
        (share.entry(), desktop_entry(&bin).into_bytes(), 0o644),
        (share.icon(), ICON.to_vec(), 0o644),
        (
            under(Path::new(Package::MARK)),
            format!("{}\n", package.word()).into_bytes(),
            0o644,
        ),
    ];
    let mut wrote = Vec::new();
    for (path, data, mode) in files {
        write(&path, &data, mode)?;
        wrote.push(path);
    }
    Ok(wrote)
}

/// [`package_root`] for the command line: `<folder> deb|rpm`.
pub fn package_root_main(args: &[String]) -> i32 {
    let (Some(root), Some(package), None) = (
        args.first(),
        args.get(1).and_then(|w| Package::of_word(w)),
        args.get(2),
    ) else {
        eprintln!("usage: nerve-node-desktop {PACKAGE_ROOT_ARG} <folder> deb|rpm");
        return 2;
    };
    let r = std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|exe| package_root(Path::new(root), &exe, package));
    match r {
        Ok(wrote) => {
            for p in wrote {
                println!("{}", p.display());
            }
            0
        }
        Err(e) => {
            eprintln!("nerve-node-desktop: {e}");
            1
        }
    }
}

/// The desktop entry: the menu's "Nerve", which opens `bin`, also with a
/// `nerve://` link. Desktop Entry 1.4, the newest that the
/// desktop-file-validate of Ubuntu 22.04 takes; it uses nothing newer.
pub fn desktop_entry(bin: &Path) -> String {
    let exec = bin.display().to_string();
    // Exec quotes a path with a space or a quote in it, escaping as the
    // specification says.
    let exec = if exec.contains([' ', '"', '\\', '\'', '$', '`']) {
        let escaped: String = exec
            .chars()
            .flat_map(|c| match c {
                '"' | '`' | '$' | '\\' => vec!['\\', c],
                c => vec![c],
            })
            .collect();
        format!("\"{}\"", escaped.replace('\\', "\\\\"))
    } else {
        exec
    };
    format!(
        "[Desktop Entry]
Type=Application
Version=1.4
Name=Nerve
GenericName=Nerve node
Comment=Decide what your Nerve centers may do on this machine
Exec={exec} %u
Icon={PROGRAM}
Terminal=false
Categories=System;Security;
Keywords=nerve;node;center;agent;pairing;
MimeType={MIME};
StartupNotify=true
StartupWMClass={PROGRAM}
"
    )
}

const DEFAULTS: &str = "[Default Applications]";

/// `mimeapps` with `id` as the default for `mime`, the rest as it was.
pub fn with_default(mimeapps: &str, mime: &str, id: &str) -> String {
    let line = format!("{mime}={id}");
    let mut out = Vec::new();
    let mut section = "";
    let mut put = false;
    for l in mimeapps.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            if section == DEFAULTS && !put {
                // After the section's last line, before the blank ones.
                let at = out
                    .iter()
                    .rposition(|l: &String| !l.trim().is_empty())
                    .map_or(0, |i| i + 1);
                out.insert(at, line.clone());
                put = true;
            }
            section = if t == DEFAULTS { DEFAULTS } else { "other" };
        } else if section == DEFAULTS && key_of(t) == Some(mime) {
            if !put {
                out.push(line.clone());
                put = true;
            }
            continue;
        }
        out.push(l.to_string());
    }
    if !put {
        if section != DEFAULTS {
            if out.last().is_some_and(|l| !l.trim().is_empty()) {
                out.push(String::new());
            }
            out.push(DEFAULTS.into());
        }
        out.push(line);
    }
    out.join("\n") + "\n"
}

/// `mimeapps` without `id` as the default for `mime`; another program's
/// default stays.
pub fn without_default(mimeapps: &str, mime: &str, id: &str) -> String {
    let mut section = "";
    let mut out = Vec::new();
    for l in mimeapps.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            section = if t == DEFAULTS { DEFAULTS } else { "other" };
        } else if section == DEFAULTS
            && key_of(t) == Some(mime)
            && t.split_once('=').is_some_and(|(_, v)| v.trim() == id)
        {
            continue;
        }
        out.push(l);
    }
    if out.is_empty() {
        return String::new();
    }
    out.join("\n") + "\n"
}

fn key_of(line: &str) -> Option<&str> {
    line.split_once('=').map(|(k, _)| k.trim())
}

/// Writes `data` to `path` through a file beside it, readable by all.
fn write(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    nerve_node::service::write_file(path, data, mode)
}

/// The texts of Nerve's entry in Apps & features on Windows, for the
/// program `bin` of `version`: Uninstall there runs `bin` with
/// [`UNINSTALL_ARG`]; a quiet one (winget) runs its `uninstall`, which keeps
/// the data.
pub fn apps_entry(bin: &Path, version: &str) -> Vec<(&'static str, String)> {
    let exe = bin.display().to_string();
    let folder = bin
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    vec![
        ("DisplayName", "Nerve".to_string()),
        ("Publisher", "Nerve Protocol".to_string()),
        ("DisplayVersion", version.to_string()),
        ("DisplayIcon", format!("\"{exe}\",0")),
        ("UninstallString", format!("\"{exe}\" {UNINSTALL_ARG}")),
        ("QuietUninstallString", format!("\"{exe}\" uninstall")),
        ("InstallLocation", folder),
        ("URLInfoAbout", env!("CARGO_PKG_REPOSITORY").to_string()),
        (
            "Comments",
            "Decide what your Nerve centers may do on this machine".to_string(),
        ),
    ]
}

/// The Start menu shortcut, the URL protocol and the Apps & features entry.
#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows_sys::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RegDeleteTreeW, RegSetKeyValueW,
    };
    use windows_sys::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
    use windows_sys::core::{GUID, HRESULT};

    use super::SCHEME;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The shortcut in the Start menu of all users.
    fn shortcut() -> PathBuf {
        let data = std::env::var_os("ProgramData")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("C:\\ProgramData"), PathBuf::from);
        data.join("Microsoft\\Windows\\Start Menu\\Programs\\Nerve.lnk")
    }

    fn classes() -> String {
        format!("Software\\Classes\\{SCHEME}")
    }

    /// The entry in Apps & features (Settings) and Programs and Features.
    const UNINSTALL_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Nerve";

    /// The version `bin` says: the program installed, which is not this one
    /// when an older one installs a newer.
    fn version_of(bin: &Path) -> String {
        std::process::Command::new(bin)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                let said = String::from_utf8_lossy(&o.stdout);
                said.trim()
                    .strip_prefix(super::PROGRAM)
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
    }

    /// Puts Nerve in Apps & features: its name, publisher, version and
    /// icon, and Uninstall, which opens the app's uninstall at `bin` (the
    /// app asks keep or delete, then the rights).
    fn put_entry(bin: &Path) -> Result<(), String> {
        for (name, value) in super::apps_entry(bin, &version_of(bin)) {
            set_value(UNINSTALL_KEY, Some(name), &value)?;
        }
        // One program, nothing to change or repair; its size in KB.
        let size = std::fs::metadata(bin).map_or(0, |m| m.len().div_ceil(1024)) as u32;
        for (name, value) in [("NoModify", 1), ("NoRepair", 1), ("EstimatedSize", size)] {
            set_dword(UNINSTALL_KEY, name, value)?;
        }
        Ok(())
    }

    /// Deletes `key` below HKEY_LOCAL_MACHINE; `false` when it was not there.
    fn delete_key(key: &str) -> Result<bool, String> {
        let k = wide(key);
        // SAFETY: a NUL-terminated key below HKEY_LOCAL_MACHINE.
        let e = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, k.as_ptr()) };
        match e {
            0 => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            e => Err(format!(
                "HKEY_LOCAL_MACHINE\\{key}: {}",
                std::io::Error::from_raw_os_error(e as i32)
            )),
        }
    }

    pub fn install(bin: &Path) -> Result<Vec<String>, String> {
        let mut did = Vec::new();
        let link = shortcut();
        make_shortcut(&link, bin)?;
        did.push(format!("put Nerve in the Start menu ({})", link.display()));
        let exe = bin.display().to_string();
        let key = classes();
        for (sub, name, value) in [
            ("", None, "URL:Nerve link".to_string()),
            ("", Some("URL Protocol"), String::new()),
            ("\\DefaultIcon", None, format!("\"{exe}\",0")),
            ("\\shell\\open\\command", None, format!("\"{exe}\" \"%1\"")),
        ] {
            set_value(&format!("{key}{sub}"), name, &value)?;
        }
        did.push(format!(
            "nerve:// links open in Nerve (HKEY_LOCAL_MACHINE\\{key})"
        ));
        associations_changed();
        put_entry(bin)?;
        did.push("put Nerve in Apps & features, where Uninstall removes it".to_string());
        Ok(did)
    }

    pub fn uninstall(_bin: &Path) -> Result<Vec<String>, String> {
        let mut did = Vec::new();
        let link = shortcut();
        match std::fs::remove_file(&link) {
            Ok(()) => did.push("removed Nerve from the Start menu".to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", link.display())),
        }
        if delete_key(&classes())? {
            did.push("nerve:// links no longer open in Nerve".to_string());
            associations_changed();
        }
        if delete_key(UNINSTALL_KEY)? {
            did.push("removed Nerve from Apps & features".to_string());
        }
        Ok(did)
    }

    /// Tells Explorer that a link handler changed.
    fn associations_changed() {
        // SAFETY: a notice without items.
        unsafe {
            SHChangeNotify(
                SHCNE_ASSOCCHANGED as i32,
                SHCNF_IDLIST,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
    }

    fn set_value(key: &str, name: Option<&str>, value: &str) -> Result<(), String> {
        let k = wide(key);
        let n = name.map(wide);
        let v = wide(value);
        // SAFETY: NUL-terminated strings; the data is the value's UTF-16
        // with its NUL, its length in bytes.
        let e = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                n.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                REG_SZ,
                v.as_ptr().cast(),
                (v.len() * 2) as u32,
            )
        };
        if e != 0 {
            return Err(format!(
                "HKEY_LOCAL_MACHINE\\{key}: {}",
                std::io::Error::from_raw_os_error(e as i32)
            ));
        }
        Ok(())
    }

    fn set_dword(key: &str, name: &str, value: u32) -> Result<(), String> {
        let k = wide(key);
        let n = wide(name);
        // SAFETY: NUL-terminated strings; the data is the four bytes of
        // `value`.
        let e = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                n.as_ptr(),
                REG_DWORD,
                (&value as *const u32).cast(),
                4,
            )
        };
        if e != 0 {
            return Err(format!(
                "HKEY_LOCAL_MACHINE\\{key}: {}",
                std::io::Error::from_raw_os_error(e as i32)
            ));
        }
        Ok(())
    }

    const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
    const IID_SHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
    const IID_PERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);

    // The slots of the methods used, in the vtables of IShellLinkW and
    // IPersistFile (IUnknown's three come first in both).
    const QUERY_INTERFACE: usize = 0;
    const RELEASE: usize = 2;
    const SET_DESCRIPTION: usize = 7;
    const SET_WORKING_DIRECTORY: usize = 9;
    const SET_ICON_LOCATION: usize = 17;
    const SET_PATH: usize = 20;
    const SAVE: usize = 6;

    type WithText = unsafe extern "system" fn(*mut c_void, *const u16) -> HRESULT;
    type WithIcon = unsafe extern "system" fn(*mut c_void, *const u16, i32) -> HRESULT;
    type Query = unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT;
    type Release = unsafe extern "system" fn(*mut c_void) -> u32;
    type Save = unsafe extern "system" fn(*mut c_void, *const u16, i32) -> HRESULT;

    /// The method in `slot` of the COM object `this`.
    unsafe fn method(this: *mut c_void, slot: usize) -> *const c_void {
        // SAFETY: a COM object starts with its vtable's address; the caller
        // names a slot the interface has.
        unsafe { *(*(this as *const *const *const c_void)).add(slot) }
    }

    fn check(what: &str, hr: HRESULT) -> Result<(), String> {
        if hr < 0 {
            return Err(format!("the Start menu entry: {what} failed (0x{hr:08x})"));
        }
        Ok(())
    }

    /// Writes the shortcut `link` to `bin` through the shell's ShellLink
    /// object, as Explorer makes one.
    fn make_shortcut(link: &Path, bin: &Path) -> Result<(), String> {
        if let Some(dir) = link.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        // SAFETY: COM on this thread for the calls below, ended again only
        // when this call started it; every interface is released.
        unsafe {
            let started = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) >= 0;
            let r = (|| {
                let mut shell: *mut c_void = std::ptr::null_mut();
                check(
                    "CoCreateInstance(ShellLink)",
                    CoCreateInstance(
                        &CLSID_SHELL_LINK,
                        std::ptr::null_mut(),
                        CLSCTX_INPROC_SERVER,
                        &IID_SHELL_LINK_W,
                        &mut shell,
                    ),
                )?;
                let release = |o: *mut c_void| {
                    let f: Release = std::mem::transmute(method(o, RELEASE));
                    f(o);
                };
                let r = (|| {
                    let exe = wide(&bin.display().to_string());
                    let dir = wide(
                        &bin.parent()
                            .map(|d| d.display().to_string())
                            .unwrap_or_default(),
                    );
                    let about = wide("Decide what your Nerve centers may do on this machine");
                    let f: WithText = std::mem::transmute(method(shell, SET_PATH));
                    check("SetPath", f(shell, exe.as_ptr()))?;
                    let f: WithText = std::mem::transmute(method(shell, SET_WORKING_DIRECTORY));
                    check("SetWorkingDirectory", f(shell, dir.as_ptr()))?;
                    let f: WithText = std::mem::transmute(method(shell, SET_DESCRIPTION));
                    check("SetDescription", f(shell, about.as_ptr()))?;
                    let f: WithIcon = std::mem::transmute(method(shell, SET_ICON_LOCATION));
                    check("SetIconLocation", f(shell, exe.as_ptr(), 0))?;
                    let mut file: *mut c_void = std::ptr::null_mut();
                    let q: Query = std::mem::transmute(method(shell, QUERY_INTERFACE));
                    check(
                        "QueryInterface(IPersistFile)",
                        q(shell, &IID_PERSIST_FILE, &mut file),
                    )?;
                    let path = wide(&link.display().to_string());
                    let save: Save = std::mem::transmute(method(file, SAVE));
                    let saved = check("Save", save(file, path.as_ptr(), 1));
                    release(file);
                    saved
                })();
                release(shell);
                r
            })();
            if started {
                CoUninitialize();
            }
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_handler_goes_in_and_out_and_leaves_the_rest() {
        let id = "nerve-node-desktop.desktop";
        let empty = with_default("", MIME, id);
        assert_eq!(empty, format!("[Default Applications]\n{MIME}={id}\n"));
        assert_eq!(
            without_default(&empty, MIME, id),
            "[Default Applications]\n"
        );

        let theirs = "[Added Associations]\nx-scheme-handler/nerve=other.desktop\n\n[Default Applications]\ntext/plain=gedit.desktop\nx-scheme-handler/nerve=old.desktop\n";
        let ours = with_default(theirs, MIME, id);
        assert_eq!(
            ours,
            format!(
                "[Added Associations]\nx-scheme-handler/nerve=other.desktop\n\n[Default Applications]\ntext/plain=gedit.desktop\n{MIME}={id}\n"
            )
        );
        // Again changes nothing.
        assert_eq!(with_default(&ours, MIME, id), ours);
        let back = without_default(&ours, MIME, id);
        assert!(back.contains("text/plain=gedit.desktop"));
        assert!(back.contains("other.desktop"));
        assert!(!back.contains(id));
        // Another program's default is not ours to remove.
        assert_eq!(without_default(theirs, MIME, id), theirs);
        let before = "[Default Applications]\ntext/plain=gedit.desktop\n\n[Removed Associations]\n";
        assert_eq!(
            with_default(before, MIME, id),
            format!(
                "[Default Applications]\ntext/plain=gedit.desktop\n{MIME}={id}\n\n[Removed Associations]\n"
            )
        );

        // A file without the section gets it at its end.
        let other = "[Added Associations]\ntext/plain=gedit.desktop\n";
        assert_eq!(
            with_default(other, MIME, id),
            format!("{other}\n[Default Applications]\n{MIME}={id}\n")
        );
    }

    #[test]
    fn the_desktop_entry_opens_the_installed_program_with_a_link() {
        let e = desktop_entry(Path::new("/usr/local/bin/nerve-node-desktop"));
        assert!(e.starts_with("[Desktop Entry]\n"));
        assert!(e.contains("\nExec=/usr/local/bin/nerve-node-desktop %u\n"));
        assert!(e.contains("\nMimeType=x-scheme-handler/nerve;\n"));
        assert!(e.contains("\nIcon=nerve-node-desktop\n"));
        let e = desktop_entry(Path::new("/opt/my apps/nerve-node-desktop"));
        assert!(
            e.contains("\nExec=\"/opt/my apps/nerve-node-desktop\" %u\n"),
            "{e}"
        );
    }

    #[test]
    fn apps_and_features_uninstalls_with_the_app_at_its_place() {
        let bin = Path::new(r"C:\Program Files\Nerve\nerve-node-desktop.exe");
        let entry: std::collections::HashMap<_, _> = apps_entry(bin, "0.0.6").into_iter().collect();
        assert_eq!(entry["DisplayName"], "Nerve");
        assert_eq!(entry["DisplayVersion"], "0.0.6");
        assert_eq!(
            entry["UninstallString"],
            format!(r#""C:\Program Files\Nerve\nerve-node-desktop.exe" {UNINSTALL_ARG}"#)
        );
        // A quiet uninstall without a window keeps the data: no --purge.
        assert_eq!(
            entry["QuietUninstallString"],
            r#""C:\Program Files\Nerve\nerve-node-desktop.exe" uninstall"#
        );
        // The silent install is the program's `install`, which a command
        // line takes as such (and which needs an administrator).
        let args: Vec<String> = SILENT_COMMAND.iter().map(|a| a.to_string()).collect();
        assert_eq!(args, ["install"]);
        assert!(nerve_node::owner::args_need_admin(&args));
        assert_eq!(
            entry["DisplayIcon"],
            r#""C:\Program Files\Nerve\nerve-node-desktop.exe",0"#
        );
        assert!(!entry["Publisher"].is_empty());
    }

    /// Without update-desktop-database the install goes on, and says what
    /// did not register.
    #[cfg(not(windows))]
    #[test]
    fn a_missing_cache_tool_is_said_and_the_rest_installed() {
        let d = tempfile::tempdir().unwrap();
        let p = Places {
            refresh: true,
            cache_tool: "nerve-test-no-update-desktop-database",
            ..Places::under(d.path())
        };
        let did = p.install(&d.path().join("nerve-node-desktop")).unwrap();
        assert!(p.entry().exists() && p.mimeapps.exists());
        let warning = did.iter().find(|l| l.starts_with("Warning:"));
        assert!(
            warning.is_some_and(|w| w.contains("nerve-test-no-update-desktop-database")
                && w.contains("desktop-file-utils")),
            "{did:?}"
        );
        assert!(p.uninstall().is_ok());
    }

    /// The package's files (#212): the program in /usr/bin, its menu entry
    /// opening it there, the icon, and the mark of the package's kind.
    /// Linux only, as the packages are.
    #[cfg(unix)]
    #[test]
    fn the_package_holds_the_program_its_menu_entry_icon_and_kind() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("nerve-node-desktop-x86_64-linux");
        std::fs::write(&exe, "the program").unwrap();
        let root = d.path().join("root");
        let wrote = package_root(&root, &exe, Package::Rpm).unwrap();
        let rel: Vec<String> = wrote
            .iter()
            .map(|p| p.strip_prefix(&root).unwrap().display().to_string())
            .collect();
        assert_eq!(
            rel,
            [
                "usr/bin/nerve-node-desktop",
                "usr/share/applications/nerve-node-desktop.desktop",
                "usr/share/icons/hicolor/scalable/apps/nerve-node-desktop.svg",
                "usr/share/nerve-node-desktop/package",
            ]
        );
        assert_eq!(std::fs::read(&wrote[0]).unwrap(), b"the program");
        let entry = std::fs::read_to_string(&wrote[1]).unwrap();
        assert!(
            entry.contains("\nExec=/usr/bin/nerve-node-desktop %u\n"),
            "{entry}"
        );
        assert_eq!(std::fs::read(&wrote[2]).unwrap(), ICON);
        assert_eq!(
            nerve_node::service::package_at(&wrote[3]),
            Some(Package::Rpm)
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&wrote[0]), 0o755);
        assert_eq!(mode(&wrote[1]), 0o644);
        assert_eq!(package_root_main(&["x".into()]), 2);
        assert_eq!(package_root_main(&["x".into(), "tar".into()]), 2);
    }

    /// The app from a package writes only the default handler: the menu
    /// entry and icon are the package's, and an earlier plain program's go.
    #[cfg(not(windows))]
    #[test]
    fn the_app_from_a_package_leaves_the_menu_entry_to_it() {
        let d = tempfile::tempdir().unwrap();
        let plain = Places::under(d.path());
        plain
            .install(&d.path().join("usr/local/bin/nerve-node-desktop"))
            .unwrap();
        let p = Places {
            packaged: true,
            ..Places::under(d.path())
        };
        let did = p.install(Path::new("/usr/bin/nerve-node-desktop")).unwrap();
        assert!(did[0].contains("the package has its own"), "{did:?}");
        assert!(!p.entry().exists() && !p.icon().exists());
        assert!(
            std::fs::read_to_string(&p.mimeapps)
                .unwrap()
                .contains("x-scheme-handler/nerve=nerve-node-desktop.desktop")
        );
        // Again writes nothing of the menu's.
        let did = p.install(Path::new("/usr/bin/nerve-node-desktop")).unwrap();
        assert_eq!(did.len(), 1, "{did:?}");
        assert!(!p.applications.exists() || !p.entry().exists());
        p.uninstall().unwrap();
        assert!(!p.mimeapps.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn the_parts_come_and_go_and_the_desktop_entry_is_valid() {
        let d = tempfile::tempdir().unwrap();
        let p = Places::under(d.path());
        let bin = d.path().join("usr/local/bin/nerve-node-desktop");
        let did = p.install(&bin).unwrap();
        assert_eq!(did.len(), 2, "{did:?}");
        assert_eq!(std::fs::read(p.icon()).unwrap(), ICON);
        let entry = std::fs::read_to_string(p.entry()).unwrap();
        assert!(entry.contains(&format!("Exec={} %u", bin.display())));
        assert!(
            std::fs::read_to_string(&p.mimeapps)
                .unwrap()
                .contains("x-scheme-handler/nerve=nerve-node-desktop.desktop")
        );
        // desktop-file-validate, where the desktop's tools are installed.
        if let Ok(o) = std::process::Command::new("desktop-file-validate")
            .arg(p.entry())
            .output()
        {
            assert!(
                o.status.success() && o.stdout.is_empty(),
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
        }
        // Again puts them back.
        std::fs::remove_file(p.entry()).unwrap();
        p.install(&bin).unwrap();
        assert!(p.entry().exists());
        // What update-desktop-database writes (refresh is off here).
        std::fs::write(
            p.applications.join("mimeinfo.cache"),
            "[MIME Cache]\nx-scheme-handler/nerve=nerve-node-desktop.desktop;\n",
        )
        .unwrap();
        let did = p.uninstall().unwrap();
        assert_eq!(did.len(), 2, "{did:?}");
        assert!(!p.entry().exists() && !p.icon().exists() && !p.mimeapps.exists());
        // No folder install made stays, and no cache that names nothing:
        // a cache with another entry stays.
        assert!(p.applications.exists());
        std::fs::write(p.applications.join("mimeinfo.cache"), "[MIME Cache]\n").unwrap();
        p.uninstall().unwrap();
        assert!(!p.icons.parent().unwrap().exists() && !p.applications.exists());
        // Nothing left says nothing.
        assert!(p.uninstall().unwrap().is_empty());
    }
}
