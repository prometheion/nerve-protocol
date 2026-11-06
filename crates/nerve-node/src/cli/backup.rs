//! `nerve-node backup` and `restore`: the node in one file under a
//! passphrase (crate::backup).

use super::*;

/// `backup`: the node's settings and keys in one file, under a passphrase.
pub(super) async fn backup(
    paths: NodePaths,
    file: PathBuf,
    include_keyring: bool,
    overwrite: bool,
    passphrase_file: Option<PathBuf>,
    out: &mut dyn Write,
) -> Result<(), String> {
    // A command of a center must not take the node's keys out under a
    // passphrase of its own.
    owner_check(&[&paths]).await?;
    let (cfg, _) = read_config(&paths).await?;
    let pass = crate::prompt::passphrase(passphrase_file.as_deref(), out, true)?;
    let opts = crate::backup::BackupOpts {
        include_keyring,
        overwrite,
        rounds: nerve_transport::backup::ITERATIONS,
    };
    let r = crate::backup::backup(&paths, &cfg, &file, &pass, &opts)?;
    crate::backup::print_backup(&r, &file, out);
    json::also("backup", crate::backup::backup_data(&r, &file));
    Ok(())
}

/// `restore`: the node as a backup of it holds it.
pub(super) async fn restore(
    paths: NodePaths,
    file: PathBuf,
    replace: bool,
    secret_storage: Option<String>,
    without_proxy: bool,
    passphrase_file: Option<PathBuf>,
    out: &mut dyn Write,
) -> Result<(), String> {
    owner_check(&[&paths]).await?;
    let bytes = crate::caller_file::read(&file)?;
    let kind = nerve_transport::backup::kind_of(&bytes)?;
    if kind != nerve_transport::backup::Kind::Node {
        return Err(format!(
            "this is the backup of a {}, not of a node: restore it with `nerve-center restore`",
            kind.word()
        ));
    }
    let storage = secret_storage
        .map(|s| parse_enum::<SecretStorage>(&s, "file or keyring"))
        .transpose()?;
    let pass = crate::prompt::passphrase(passphrase_file.as_deref(), out, false)?;
    let parsed = crate::backup::open(&bytes, &pass)?;
    // An owner restores what an owner may change, nothing that
    // picks the account or program commands run as.
    if crate::owner::owner_running().is_some()
        && let Some(key) = crate::backup::root_only_change(&paths, &parsed)
    {
        return Err(crate::owner::restore_needs_admin(key));
    }
    let opts = crate::backup::RestoreOpts {
        replace,
        secret_storage: storage,
        without_proxy,
    };
    let r = crate::backup::restore(&paths, &parsed, &opts)?;
    crate::backup::print_restore(&r, &parsed, out);
    json::also("restored", crate::backup::restore_data(&r, &parsed));
    Ok(())
}
