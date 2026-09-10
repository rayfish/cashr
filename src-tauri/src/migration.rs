//! One-time namespace conversion. Source names come from the prior data directory;
//! the running wallet only reads the current schema and encryption format.
use crate::{nwc::NwcService, state::AppState};
use anyhow::{anyhow, bail, ensure, Context, Result};
use nostr::{key::Keys, nips::nip44::Nip44};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::account::AccountId;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

const MARKER: &str = "namespace-migration.json";
#[derive(Default)]
pub struct MigrationLock(Mutex<()>);
#[derive(Serialize, Deserialize)]
struct Progress {
    namespace: String,
    completed: BTreeSet<String>,
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

pub fn prepare(app: &AppHandle) -> Result<()> {
    let destination = app.path().app_data_dir()?;
    let Some(source) = previous_directory(&destination)? else {
        return Ok(());
    };
    // The source has encrypted SQLite files, so its owner must be closed before
    // taking a filesystem snapshot including WAL files. Never stop it for the user.
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/bin/pgrep")
            .args(["-x", "cashr"])
            .output()?;
        ensure!(
            output.status.success() || output.status.code() == Some(1),
            "Could not check for another Cashr instance."
        );
        let other = String::from_utf8(output.stdout)?
            .lines()
            .filter_map(|s| s.parse::<u32>().ok())
            .any(|pid| pid != std::process::id());
        ensure!(
            !other,
            "Quit the other Cashr instance before transferring wallet data, then open Cashr again."
        );
    }
    copy_previous(&source, &destination)
}

fn previous_directory(destination: &Path) -> Result<Option<PathBuf>> {
    if destination.join("signer.db").exists() || destination.join(MARKER).exists() {
        return Ok(None);
    }
    if destination.exists() && fs::read_dir(destination)?.next().is_some() {
        return Ok(None);
    }
    let Some(parent) = destination.parent() else {
        bail!("Missing application data directory");
    };
    if !parent.exists() {
        return Ok(None);
    }
    let name = destination
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("Invalid application namespace"))?;
    if name == "xyz.rayfish.cashr" {
        let previous = parent.join("com.dgrr.cashr");
        // Prefer the last Cashr installation over any older prototype copies.
        // If Cashr was never opened, retain the previous namespace discovery.
        if previous.join("signer.db").is_file() {
            return Ok(Some(previous));
        }
        return previous_directory(&previous);
    }
    let publisher = name
        .rsplit_once('.')
        .ok_or_else(|| anyhow!("Invalid application namespace"))?
        .0;
    let mut found = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            continue;
        };
        if !entry.file_type()?.is_dir()
            || path == destination
            || !name.starts_with(&format!("{publisher}."))
        {
            continue;
        }
        let namespace = name.rsplit('.').next().unwrap_or_default();
        if valid_namespace(namespace)
            && path.join("signer.db").is_file()
            && path.join("keys").is_dir()
            && path.join("unlock.passphrase").is_file()
        {
            found.push(path);
        }
    }
    ensure!(found.len() <= 1, "Multiple previous wallets found. Move the intended data directory to the Cashr data location before opening.");
    Ok(found.pop())
}

fn copy_previous(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(source)?.file_type().is_dir(),
        "Cannot migrate a wallet data directory that is not a regular directory"
    );
    let namespace = source
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.rsplit('.').next())
        .ok_or_else(|| anyhow!("Invalid source namespace"))?;
    ensure!(valid_namespace(namespace), "Invalid source namespace");
    let stage = destination.with_file_name(format!(
        ".cashr-transfer-{}",
        Keys::generate().public_key().to_hex()
    ));
    fs::create_dir(&stage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    }
    let result = (|| {
        copy_directory(source, &stage)?;
        // Changing only the publisher does not change the cashr encryption
        // namespace. Preserve any older, partially completed conversion marker.
        if namespace != "cashr" && !stage.join(MARKER).exists() {
            write_progress(
                &stage,
                &Progress {
                    namespace: namespace.into(),
                    completed: BTreeSet::new(),
                },
            )?;
        }
        if destination.exists() {
            fs::remove_dir(destination)
                .context("Cashr's destination must be empty before migration")?;
        }
        fs::rename(&stage, destination)?;
        sync_directory(destination.parent().unwrap())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        ensure!(
            !kind.is_symlink(),
            "Cannot migrate symbolic links in wallet data"
        );
        if kind.is_dir() {
            fs::create_dir(&target)?;
            fs::set_permissions(&target, entry.metadata()?.permissions())?;
            copy_directory(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)?;
            fs::File::open(target)?.sync_all()?;
        } else {
            bail!("Unsupported file in wallet data");
        }
    }
    sync_directory(destination)
}
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn write_progress(directory: &Path, progress: &Progress) -> Result<()> {
    let temporary = directory.join("namespace-migration.tmp");
    fs::write(&temporary, serde_json::to_vec(progress)?)?;
    fs::File::open(&temporary)?.sync_all()?;
    fs::rename(temporary, directory.join(MARKER))?;
    sync_directory(directory)
}

pub fn ensure_account(app: &AppHandle, state: &AppState, account: i64) -> Result<()> {
    let id = AccountId::new(account);
    let public = state.storage.account(id)?.identity_public_key;
    convert(
        app,
        state,
        public.to_hex(),
        |namespace| {
            Ok(state
                .session
                .vault()
                .storage_seed_for_migration(id, namespace)?)
        },
        |secret| Ok(state.session.vault().nip44_encrypt(id, &public, secret)?),
    )
}

pub fn ensure_identity(app: &AppHandle, state: &AppState, identity: &Keys) -> Result<()> {
    convert(
        app,
        state,
        identity.public_key().to_hex(),
        |namespace| {
            Ok(signer_core::vault::storage_seed_for_migration(
                identity, namespace,
            ))
        },
        |secret| Ok(identity.nip44_encrypt(&identity.public_key(), secret)?),
    )
}

fn convert(
    app: &AppHandle,
    state: &AppState,
    public: String,
    seed: impl Fn(&str) -> Result<[u8; 64]>,
    seal: impl Fn(&str) -> Result<String>,
) -> Result<()> {
    let directory = app.path().app_data_dir()?;
    if !directory.join(MARKER).exists() {
        return Ok(());
    }
    let lock = app.state::<MigrationLock>();
    let _lock = lock.0.lock().unwrap_or_else(|e| e.into_inner());
    let mut progress: Progress = serde_json::from_slice(&fs::read(directory.join(MARKER))?)?;
    if progress.completed.contains(&public) {
        return Ok(());
    }
    ensure!(
        valid_namespace(&progress.namespace),
        "Invalid migration namespace"
    );
    let previous = Zeroizing::new(seed(&progress.namespace)?);
    let current = Zeroizing::new(seed("cashr")?);
    // Preserve NWC transport keys before changing the domain that derived them.
    if let Some(account) = state
        .accounts()?
        .into_iter()
        .find(|a| a.identity_public_key.to_hex() == public)
    {
        app.state::<NwcService>()
            .preserve_connection_keys(account.id.get(), &previous, seal)?;
    }
    convert_wallets(
        &directory.join("wallets"),
        &public,
        &progress.namespace,
        &previous,
        &current,
    )?;
    progress.completed.insert(public);
    write_progress(&directory, &progress)
}

fn password(namespace: &str, seed: &[u8; 64]) -> Zeroizing<String> {
    let mut hash = Sha256::new();
    hash.update(format!("{namespace}/cashu/database/v1\0").as_bytes());
    hash.update(seed);
    Zeroizing::new(format!("{:x}", hash.finalize()))
}
fn slot(namespace: &str, seed: &[u8], mint: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(format!("{namespace}/cashu/import/v1\0").as_bytes());
    hash.update(seed);
    hash.update(mint.as_bytes());
    format!("{:x}", hash.finalize())
}
fn open_keyed(path: &Path, key: &str) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.pragma_update(None, "key", key)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, u64>(0)
    })?;
    Ok(conn)
}
fn convert_database(
    path: &Path,
    namespace: &str,
    previous: &str,
    current: &str,
) -> Result<(Zeroizing<Vec<u8>>, String)> {
    // Trying the current key first makes a crash between rekey and table rename
    // resumable. The original source directory is never modified.
    let mut conn = match open_keyed(path, current) {
        Ok(conn) => conn,
        Err(_) => {
            let conn = open_keyed(path, previous)?;
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            conn.pragma_update(None, "rekey", current)?;
            conn
        }
    };
    let tx = conn.transaction()?;
    for suffix in ["master_recovery", "wallet_profile"] {
        let old = format!("{namespace}_{suffix}");
        let new = format!("cashr_{suffix}");
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
            [&old],
            |r| r.get(0),
        )?;
        if exists && old != new {
            tx.execute_batch(&format!("ALTER TABLE \"{old}\" RENAME TO \"{new}\";"))?;
        }
    }
    let profile = tx.query_row(
        "SELECT seed,mint FROM cashr_wallet_profile WHERE id=1",
        [],
        |r| {
            Ok((
                Zeroizing::new(r.get::<_, Vec<u8>>(0)?),
                r.get::<_, String>(1)?,
            ))
        },
    )?;
    ensure!(profile.0.len() == 64, "Invalid wallet seed length");
    tx.commit()?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(conn);
    // Verify the new encryption key in an independent connection before publishing.
    drop(open_keyed(path, current)?);
    fs::File::open(path)?.sync_all()?;
    Ok(profile)
}
fn convert_wallets(
    directory: &Path,
    public: &str,
    namespace: &str,
    previous: &[u8; 64],
    current: &[u8; 64],
) -> Result<()> {
    if !directory.exists() {
        return Ok(());
    }
    let old_key = password(namespace, previous);
    let new_key = password("cashr", current);
    let original = directory.join(format!("{public}.sqlite"));
    let active = original.with_extension("active");
    let paths: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    for entry in paths {
        let path = entry.path();
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            continue;
        };
        if !entry.file_type()?.is_file()
            || !name.starts_with(&format!("{public}."))
            || !name.ends_with(".sqlite")
        {
            continue;
        }
        let (seed, mint) = convert_database(&path, namespace, &old_key, &new_key)?;
        if path == original {
            continue;
        }
        let new_slot = slot("cashr", &seed, &mint);
        let old_slot = slot(namespace, &seed, &mint);
        let destination = original.with_extension(format!("{new_slot}.sqlite"));
        if path != destination {
            ensure!(
                !destination.exists(),
                "Conflicting wallet files. Keep both copies and check the backup."
            );
            fs::rename(&path, &destination)?;
            sync_directory(directory)?;
        }
        match fs::read_to_string(&active) {
            Ok(selected) if selected == old_slot => {
                let temporary = active.with_extension("active.tmp");
                fs::write(&temporary, &new_slot)?;
                fs::File::open(&temporary)?.sync_all()?;
                fs::rename(temporary, &active)?;
                sync_directory(directory)?;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn old_database(path: &Path, key: &str, namespace: &str, seed: &[u8; 64], mint: &str) {
        let conn = Connection::open(path).unwrap();
        conn.pragma_update(None, "key", key).unwrap();
        conn.execute_batch(&format!("PRAGMA journal_mode=WAL;
            CREATE TABLE {namespace}_wallet_profile(id INTEGER PRIMARY KEY,seed BLOB,mint TEXT);
            CREATE TABLE {namespace}_master_recovery(id INTEGER PRIMARY KEY,phrase TEXT,passphrase_required INTEGER);
            CREATE TABLE cashr_recovery_scan(id INTEGER PRIMARY KEY,complete INTEGER);
            CREATE TABLE proofs(secret TEXT PRIMARY KEY,amount INTEGER,counter INTEGER);
            INSERT INTO proofs VALUES ('synthetic-unspent-proof',100000,42);
            INSERT INTO cashr_recovery_scan VALUES (1,1);")).unwrap();
        conn.execute(
            &format!("INSERT INTO {namespace}_wallet_profile VALUES (1,?,?)"),
            rusqlite::params![&seed[..], mint],
        )
        .unwrap();
        conn.execute(&format!("INSERT INTO {namespace}_master_recovery VALUES (1,?,1)"),["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]).unwrap();
    }
    #[test]
    fn snapshot_preserves_source_and_refuses_to_overwrite_existing_data() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("com.example.prototype");
        let new = root.path().join("com.example.cashr");
        fs::create_dir_all(old.join("keys")).unwrap();
        fs::write(old.join("signer.db"), "fixture metadata").unwrap();
        fs::write(old.join("unlock.passphrase"), "synthetic device key").unwrap();
        fs::write(old.join("keys/1"), "encrypted fixture").unwrap();
        assert_eq!(previous_directory(&new).unwrap(), Some(old.clone()));
        copy_previous(&old, &new).unwrap();
        assert_eq!(
            fs::read(new.join("keys/1")).unwrap(),
            fs::read(old.join("keys/1")).unwrap()
        );
        let progress: Progress =
            serde_json::from_slice(&fs::read(new.join(MARKER)).unwrap()).unwrap();
        assert_eq!(progress.namespace, "prototype");
        assert!(previous_directory(&new).unwrap().is_none());
        assert!(copy_previous(&old, &new).is_err());
        assert!(new.join("signer.db").exists());
        assert!(old.join("signer.db").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&new).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
    #[test]
    fn ambiguous_previous_directories_require_an_explicit_choice() {
        let root = tempfile::tempdir().unwrap();
        for name in ["prototype", "preview"] {
            let old = root.path().join(format!("com.example.{name}"));
            fs::create_dir_all(old.join("keys")).unwrap();
            fs::write(old.join("signer.db"), "").unwrap();
            fs::write(old.join("unlock.passphrase"), "").unwrap();
        }
        assert!(previous_directory(&root.path().join("com.example.cashr")).is_err());
    }

    fn installation(root: &Path, bundle: &str) -> PathBuf {
        let directory = root.join(bundle);
        fs::create_dir_all(directory.join("keys")).unwrap();
        fs::write(directory.join("signer.db"), "fixture metadata").unwrap();
        fs::write(directory.join("unlock.passphrase"), "synthetic device key").unwrap();
        directory
    }

    #[test]
    fn publisher_change_preserves_wallets_and_prefers_cashr_over_older_copies() {
        let root = tempfile::tempdir().unwrap();
        let old = installation(root.path(), "com.dgrr.cashr");
        installation(root.path(), "com.dgrr.byrgi");
        let new = root.path().join("xyz.rayfish.cashr");
        fs::write(old.join("keys/1"), "encrypted key fixture").unwrap();
        fs::write(old.join("nwc.sqlite"), "pairings and replay fixture").unwrap();
        fs::write(old.join("signer.db-wal"), "pending metadata fixture").unwrap();
        fs::create_dir(old.join("wallets")).unwrap();
        let key = password("cashr", &[1; 64]);
        old_database(
            &old.join("wallets/account.sqlite"),
            &key,
            "cashr",
            &[2; 64],
            "https://mint.example",
        );
        assert_eq!(previous_directory(&new).unwrap(), Some(old.clone()));
        copy_previous(&old, &new).unwrap();
        for file in [
            "signer.db",
            "signer.db-wal",
            "unlock.passphrase",
            "keys/1",
            "nwc.sqlite",
            "wallets/account.sqlite",
        ] {
            assert_eq!(
                fs::read(old.join(file)).unwrap(),
                fs::read(new.join(file)).unwrap(),
                "{file} changed during transfer"
            );
        }
        assert!(!new.join(MARKER).exists());
        let wallet = open_keyed(&new.join("wallets/account.sqlite"), &key).unwrap();
        assert_eq!(
            wallet
                .query_row("SELECT sum(amount) FROM proofs", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            100000
        );
        assert!(previous_directory(&new).unwrap().is_none());
        assert!(copy_previous(&old, &new).is_err());
    }

    #[test]
    fn publisher_change_keeps_an_unfinished_namespace_conversion() {
        let root = tempfile::tempdir().unwrap();
        let old = installation(root.path(), "com.dgrr.cashr");
        let new = root.path().join("xyz.rayfish.cashr");
        write_progress(
            &old,
            &Progress {
                namespace: "byrgi".into(),
                completed: BTreeSet::from(["converted-account".into()]),
            },
        )
        .unwrap();
        copy_previous(&old, &new).unwrap();
        assert_eq!(
            fs::read(old.join(MARKER)).unwrap(),
            fs::read(new.join(MARKER)).unwrap()
        );
    }

    #[test]
    fn publisher_change_discovers_older_installs_and_respects_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let old = installation(root.path(), "com.dgrr.byrgi");
        let new = root.path().join("xyz.rayfish.cashr");
        assert_eq!(previous_directory(&new).unwrap(), Some(old.clone()));
        copy_previous(&old, &new).unwrap();
        let progress: Progress =
            serde_json::from_slice(&fs::read(new.join(MARKER)).unwrap()).unwrap();
        assert_eq!(progress.namespace, "byrgi");
        assert!(previous_directory(&new).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn publisher_change_rejects_a_symlinked_source() {
        let root = tempfile::tempdir().unwrap();
        let source = installation(root.path(), "elsewhere");
        let link = root.path().join("com.dgrr.cashr");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        let new = root.path().join("xyz.rayfish.cashr");
        assert_eq!(previous_directory(&new).unwrap(), Some(link.clone()));
        assert!(copy_previous(&link, &new).is_err());
        assert!(!new.exists());
    }

    #[test]
    fn conversion_preserves_funds_words_counters_and_active_mint_and_can_resume() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();
        let identity = Keys::generate();
        let public = identity.public_key().to_hex();
        let previous = signer_core::vault::storage_seed_for_migration(&identity, "prototype");
        let current = signer_core::vault::wallet_storage_seed(&identity);
        assert_ne!(previous, current);
        let seed = [7; 64];
        let mint = "https://mint.example";
        let original = directory.join(format!("{public}.sqlite"));
        let old_slot = slot("prototype", &seed, mint);
        let new_slot = slot("cashr", &seed, mint);
        let old_path = original.with_extension(format!("{old_slot}.sqlite"));
        let new_path = original.with_extension(format!("{new_slot}.sqlite"));
        let old_key = password("prototype", &previous);
        let new_key = password("cashr", &current);
        old_database(&original, &old_key, "prototype", &seed, mint);
        old_database(&old_path, &old_key, "prototype", &seed, mint);
        fs::write(original.with_extension("active"), &old_slot).unwrap();
        // Simulate interruption after rekey but before the schema/filename changes.
        let conn = open_keyed(&old_path, &old_key).unwrap();
        conn.pragma_update(None, "rekey", new_key.as_str()).unwrap();
        drop(conn);
        convert_wallets(directory, &public, "prototype", &previous, &current).unwrap();
        assert!(!old_path.exists());
        assert!(new_path.exists());
        assert_eq!(
            fs::read_to_string(original.with_extension("active")).unwrap(),
            new_slot
        );
        let conn = open_keyed(&new_path, &new_key).unwrap();
        assert_eq!(
            conn.query_row("SELECT sum(amount) FROM proofs", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            100000
        );
        assert_eq!(
            conn.query_row("SELECT counter FROM proofs", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            42
        );
        assert_eq!(
            conn.query_row("SELECT seed FROM cashr_wallet_profile", [], |r| r
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            seed
        );
        assert!(conn
            .query_row(
                "SELECT passphrase_required FROM cashr_master_recovery",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        assert!(conn
            .query_row("SELECT complete FROM cashr_recovery_scan", [], |r| r
                .get::<_, bool>(0))
            .unwrap());
        let words: String = conn
            .query_row("SELECT phrase FROM cashr_master_recovery", [], |r| r.get(0))
            .unwrap();
        assert_eq!(words.split_whitespace().count(), 12);
        drop(conn);
        assert!(open_keyed(&new_path, &old_key).is_err());
        // Simulate interruption between publishing the renamed file and selection.
        fs::write(original.with_extension("active"), old_slot).unwrap();
        convert_wallets(directory, &public, "prototype", &previous, &current).unwrap();
        assert_eq!(
            fs::read_to_string(original.with_extension("active")).unwrap(),
            new_slot
        );
        assert!(open_keyed(&original, &new_key).is_ok());
    }
    #[test]
    fn namespaces_cannot_inject_sql_or_paths() {
        for name in ["", "../wallet", "x\"; DROP TABLE proofs;--", "Name", "a/b"] {
            assert!(!valid_namespace(name));
        }
        assert!(valid_namespace("prototype"));
    }
}
