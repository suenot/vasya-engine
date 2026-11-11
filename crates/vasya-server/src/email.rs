//! Email provider wiring: per-user encrypted account storage.
//!
//! Each account is one file `<data_dir>/email/<hash(user)>/<account>.enc`
//! (ChaCha20-Poly1305 under the profile master key, nonce prefixed, the owner
//! and account id bound as associated data so a file cannot be moved to
//! another user or id). The password never leaves this module in clear.

use std::path::PathBuf;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use vasya_channel_email::{ConfigStore, MailConfig};
use vasya_core::telegram::master_key::MasterKeyProvider;

pub struct EncryptedStore {
    dir: PathBuf,
    keys: Arc<dyn MasterKeyProvider>,
}

impl EncryptedStore {
    pub fn new(dir: PathBuf, keys: Arc<dyn MasterKeyProvider>) -> Self {
        Self { dir, keys }
    }

    fn user_dir(&self, user: &str) -> PathBuf {
        let hash = Sha256::digest(user.as_bytes());
        self.dir.join(
            hash[..16]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
    }

    fn path(&self, user: &str, id: &str) -> Result<PathBuf, String> {
        // Ids are server-generated UUIDs: anything else could escape the dir.
        uuid::Uuid::parse_str(id).map_err(|_| "invalid account id".to_string())?;
        Ok(self.user_dir(user).join(format!("{id}.enc")))
    }

    fn cipher(&self) -> Result<ChaCha20Poly1305, String> {
        let key = self
            .keys
            .get_or_create()
            .map_err(|_| "key unavailable".to_string())?;
        Ok(ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key"))
    }

    fn aad(user: &str, id: &str) -> Vec<u8> {
        format!("{user}\0{id}").into_bytes()
    }
}

impl ConfigStore for EncryptedStore {
    fn save(&self, user: &str, id: &str, c: &MailConfig) -> Result<(), String> {
        let path = self.path(user, id)?;
        let parent = path.parent().ok_or("bad path")?;
        std::fs::create_dir_all(parent).map_err(|_| "could not create storage")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let plain = serde_json::to_vec(c).map_err(|_| "encode failed")?;
        let aad = Self::aad(user, id);
        let sealed = self
            .cipher()?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| "encrypt failed")?;
        let tmp = path.with_extension("enc.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = options.open(&tmp)?;
            f.write_all(&nonce)?;
            f.write_all(&sealed)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err("could not save account".into());
        }
        Ok(())
    }

    fn load(&self, user: &str, id: &str) -> Result<Option<MailConfig>, String> {
        let path = self.path(user, id)?;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("could not read account".into()),
        };
        if bytes.len() <= 12 || bytes.len() > 64 * 1024 {
            return Err("invalid account file".into());
        }
        let aad = Self::aad(user, id);
        let plain = self
            .cipher()?
            .decrypt(
                Nonce::from_slice(&bytes[..12]),
                Payload {
                    msg: &bytes[12..],
                    aad: &aad,
                },
            )
            .map_err(|_| "could not decrypt account")?;
        serde_json::from_slice(&plain)
            .map(Some)
            .map_err(|_| "invalid account".into())
    }

    fn list(&self, user: &str) -> Result<Vec<(String, String)>, String> {
        let entries = match std::fs::read_dir(self.user_dir(user)) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err("could not list accounts".into()),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".enc") else {
                continue;
            };
            if let Ok(Some(c)) = self.load(user, id) {
                out.push((id.to_string(), c.email));
            }
        }
        out.sort();
        Ok(out)
    }

    fn delete(&self, user: &str, id: &str) -> Result<bool, String> {
        match std::fs::remove_file(self.path(user, id)?) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err("could not delete account".into()),
        }
    }
}
