//! Mature AES-256-GCM envelopes for recoverable, server-only credentials.

use crate::error::AppError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::Deserialize;
use std::{collections::HashSet, path::Path};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionedKey {
    kid: String,
    key: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvisionedKeys {
    active_kid: String,
    keys: Vec<ProvisionedKey>,
}
struct Material {
    kid: String,
    key: LessSafeKey,
}

/// Private keyring, intentionally without Debug or Serialize. Provisioning and
/// changing the active kid requires a verified configuration reload/restart.
pub(crate) struct CipherKeys {
    active: String,
    keys: Vec<Material>,
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 80
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl CipherKeys {
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        // Public deterministic test material, never used by configuration.
        Self {
            active: "fixture".into(),
            keys: vec![Material {
                kid: "fixture".into(),
                key: LessSafeKey::new(
                    UnboundKey::new(&AES_256_GCM, &[37u8; 32]).expect("valid fixture key"),
                ),
            }],
        }
    }
    pub(crate) fn load(path: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "PORTAL_TOKEN_KEY_FILE must be absolute"
        );
        let bytes = std::fs::read(path)
            .map_err(|_| anyhow::anyhow!("PORTAL_TOKEN_KEY_FILE cannot be read"))?;
        anyhow::ensure!(bytes.len() <= 32768, "BFF token keyring is too large");
        let document: ProvisionedKeys = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("BFF token keyring JSON is invalid"))?;
        anyhow::ensure!(
            !document.keys.is_empty()
                && document.keys.len() <= 8
                && valid_kid(&document.active_kid),
            "BFF keyring must contain 1..8 canonical kids"
        );
        let mut seen = HashSet::new();
        let mut keys = Vec::new();
        for material in document.keys {
            anyhow::ensure!(
                valid_kid(&material.kid) && seen.insert(material.kid.clone()),
                "BFF key ids must be unique"
            );
            let bytes = URL_SAFE_NO_PAD
                .decode(&material.key)
                .map_err(|_| anyhow::anyhow!("BFF token key must be canonical base64url"))?;
            anyhow::ensure!(
                bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == material.key,
                "BFF token keys must have 256 bits"
            );
            let key = UnboundKey::new(&AES_256_GCM, &bytes)
                .map_err(|_| anyhow::anyhow!("BFF token key is invalid"))?;
            keys.push(Material {
                kid: material.kid,
                key: LessSafeKey::new(key),
            });
        }
        anyhow::ensure!(
            seen.contains(&document.active_kid),
            "BFF active kid must exist in the keyring"
        );
        Ok(Self {
            active: document.active_kid,
            keys,
        })
    }

    pub(crate) fn seal(
        &self,
        record: Uuid,
        issuer: &str,
        client: Uuid,
        kind: &str,
        plain: &str,
    ) -> Result<String, AppError> {
        if plain.len() > 16384 {
            return Err(AppError::Unavailable);
        }
        let material = self
            .keys
            .iter()
            .find(|key| key.kid == self.active)
            .ok_or(AppError::Unavailable)?;
        let mut nonce = [0_u8; 12];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| AppError::Unavailable)?;
        let associated =
            format!("customer-portal-bff-aead/1\0{record}\0{issuer}\0{client}\0{kind}");
        let mut ciphertext = plain.as_bytes().to_vec();
        material
            .key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(associated.as_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| AppError::Unavailable)?;
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&ciphertext);
        Ok(format!(
            "v1.{}.{}",
            material.kid,
            URL_SAFE_NO_PAD.encode(envelope)
        ))
    }

    pub(crate) fn open(
        &self,
        record: Uuid,
        issuer: &str,
        client: Uuid,
        kind: &str,
        envelope: &str,
    ) -> Result<String, AppError> {
        if envelope.len() > 32768 {
            return Err(AppError::Unavailable);
        }
        let mut pieces = envelope.split('.');
        if pieces.next() != Some("v1") {
            return Err(AppError::Unavailable);
        }
        let kid = pieces.next().ok_or(AppError::Unavailable)?;
        let encoded = pieces.next().ok_or(AppError::Unavailable)?;
        if pieces.next().is_some() {
            return Err(AppError::Unavailable);
        }
        let material = self
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(AppError::Unavailable)?;
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AppError::Unavailable)?;
        if ciphertext.len() < 28 || URL_SAFE_NO_PAD.encode(&ciphertext) != encoded {
            return Err(AppError::Unavailable);
        }
        let nonce: [u8; 12] = ciphertext[..12]
            .try_into()
            .map_err(|_| AppError::Unavailable)?;
        let associated =
            format!("customer-portal-bff-aead/1\0{record}\0{issuer}\0{client}\0{kind}");
        let plain = material
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(associated.as_bytes()),
                &mut ciphertext[12..],
            )
            .map_err(|_| AppError::Unavailable)?;
        String::from_utf8(plain.to_vec()).map_err(|_| AppError::Unavailable)
    }
}
