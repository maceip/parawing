// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Host-side blind password generator and `0600` local fallback vault (`PARAWING_VAULT_PATH`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::control;

/// Environment variable overriding the local fallback vault JSON path.
pub const VAULT_PATH_ENV: &str = "PARAWING_VAULT_PATH";

const SECRET_ALPHABET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+";
const SECRET_LEN: usize = 24;

/// Generated host-side password account scoped to `(origin, username)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAccount {
    /// Stable vault account identifier (`acct_1`, `acct_2`, ...).
    pub account_id: String,
    /// Bound origin (`scheme://host[:port]`).
    pub origin: String,
    /// Account username or email.
    pub username: String,
    /// High-entropy host-only password secret (never transmitted to agents).
    pub secret: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

/// Persisted collection of host-side `VaultAccount` entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStore {
    /// Stored password accounts.
    pub accounts: Vec<VaultAccount>,
}

/// Resolves the vault file path from `PARAWING_VAULT_PATH` or `/tmp/parawing-vault.json`.
pub fn vault_path() -> PathBuf {
    std::env::var(VAULT_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/parawing-vault.json"))
}

/// Generates a 24-character high-entropy secret without modulo bias via rejection sampling.
pub fn generate_random_secret() -> Result<String, String> {
    let alphabet_len = SECRET_ALPHABET.len();
    let usable_limit = (256 / alphabet_len) * alphabet_len;
    let mut out = String::with_capacity(SECRET_LEN);
    while out.len() < SECRET_LEN {
        let batch = crate::webauthn::random::bytes(SECRET_LEN * 2)?;
        for byte in batch {
            let b = usize::from(byte);
            if b < usable_limit {
                out.push(SECRET_ALPHABET[b % alphabet_len] as char);
                if out.len() == SECRET_LEN {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// Loads a `VaultStore` from `path`, returning an empty store if absent.
pub fn load_store_from(path: &Path) -> VaultStore {
    let Ok(raw) = fs::read_to_string(path) else {
        return VaultStore::default();
    };
    serde_json::from_str::<VaultStore>(&raw).unwrap_or_default()
}

/// Loads the default `VaultStore` from `vault_path()`.
pub fn load_store() -> VaultStore {
    load_store_from(&vault_path())
}

/// Writes `store` to `path` with `0600` owner-only permissions on Unix.
pub fn save_store_to(path: &Path, store: &VaultStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let serialized =
        serde_json::to_string_pretty(store).map_err(|e| format!("serialize vault: {e}"))?;
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("open vault {}: {e}", path.display()))?;
    file.write_all(serialized.as_bytes())
        .map_err(|e| format!("write vault {}: {e}", path.display()))?;
    file.flush()
        .map_err(|e| format!("flush vault {}: {e}", path.display()))
}

/// Looks up `(origin, username)` in `path` or generates and persists a new 24-char secret.
pub fn get_or_create_secret_at(
    path: &Path,
    origin: &str,
    username: &str,
) -> Result<VaultAccount, String> {
    let mut store = load_store_from(path);
    if let Some(existing) = store
        .accounts
        .iter()
        .find(|a| a.origin == origin && a.username == username)
    {
        return Ok(existing.clone());
    }
    let secret = generate_random_secret()?;
    let account = VaultAccount {
        account_id: format!("acct_{}", store.accounts.len() + 1),
        origin: origin.to_string(),
        username: username.to_string(),
        secret,
        created_at: control::now_iso(),
    };
    store.accounts.push(account.clone());
    save_store_to(path, &store)?;
    Ok(account)
}

/// Looks up or creates a secret in `vault_path()`.
pub fn get_or_create_secret(origin: &str, username: &str) -> Result<VaultAccount, String> {
    get_or_create_secret_at(&vault_path(), origin, username)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_idempotent_0600_vault_accounts_with_distinct_secrets() {
        let path =
            std::env::temp_dir().join(format!("parawing-vault-test-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);

        let a1 = get_or_create_secret_at(&path, "https://example.com", "ada").unwrap();
        let a2 = get_or_create_secret_at(&path, "https://example.com", "ada").unwrap();
        let b1 = get_or_create_secret_at(&path, "https://other.example", "ada").unwrap();

        assert_eq!(a1.secret.len(), SECRET_LEN);
        assert_eq!(a1, a2);
        assert_ne!(a1.secret, b1.secret);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_file(&path);
    }
}
