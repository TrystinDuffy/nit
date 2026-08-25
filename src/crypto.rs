use std::collections::BTreeMap;

use anyhow::{bail, ensure, Context, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"NITVLT01";
const VERSION: u8 = 1;
const WRAP_INFO: &[u8] = b"nit/v1/wrap-key";
const PAYLOAD_AAD_LABEL: &[u8] = b"nit/v1/payload";
const MAX_SECRETS: usize = 10_000;
const MAX_NAME_LEN: usize = 1_024;
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient {
    pub serial: u32,
    pub slot: u8,
    pub public_key: [u8; 32],
}

#[derive(Debug, Default)]
pub struct Vault {
    secrets: BTreeMap<String, String>,
}

impl Vault {
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.secrets.keys().map(String::as_str)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(String::as_str)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }

    pub fn insert(&mut self, name: String, value: String) -> Option<String> {
        self.secrets.insert(name, value)
    }

    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.secrets.remove(name)
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(self.secrets.len() <= MAX_SECRETS, "too many secrets");
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(&(self.secrets.len() as u32).to_be_bytes());
        for (name, value) in &self.secrets {
            ensure!(!name.is_empty(), "secret names cannot be empty");
            ensure!(name.len() <= MAX_NAME_LEN, "secret name is too long");
            ensure!(value.len() <= MAX_VALUE_LEN, "secret value is too long");
            bytes.extend_from_slice(&(name.len() as u32).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        Ok(bytes)
    }

    fn decode(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let mut cursor = Cursor::new(&bytes);
        let count = cursor.u32()? as usize;
        ensure!(count <= MAX_SECRETS, "vault contains too many secrets");
        let mut secrets = BTreeMap::new();
        for _ in 0..count {
            let name_len = cursor.u32()? as usize;
            ensure!(
                name_len > 0 && name_len <= MAX_NAME_LEN,
                "invalid secret name length"
            );
            let name = String::from_utf8(cursor.take(name_len)?.to_vec())
                .context("secret name is not UTF-8")?;
            let value_len = cursor.u32()? as usize;
            ensure!(value_len <= MAX_VALUE_LEN, "invalid secret value length");
            let value = String::from_utf8(cursor.take(value_len)?.to_vec())
                .context("secret value is not UTF-8")?;
            ensure!(
                secrets.insert(name, value).is_none(),
                "duplicate secret name"
            );
        }
        ensure!(cursor.remaining() == 0, "trailing bytes in decrypted vault");
        bytes.zeroize();
        Ok(Self { secrets })
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        for value in self.secrets.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Clone, Debug)]
pub struct Envelope {
    recipient: Recipient,
    ephemeral_public_key: [u8; 32],
    wrap_nonce: [u8; 24],
    wrapped_file_key: [u8; 48],
    file_nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn recipient(&self) -> Recipient {
        self.recipient.clone()
    }

    pub fn seal(vault: &Vault, recipient: &Recipient) -> Result<Self> {
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
        let recipient_public = PublicKey::from(recipient.public_key);
        let shared = Zeroizing::new(
            ephemeral_secret
                .diffie_hellman(&recipient_public)
                .to_bytes(),
        );
        ensure!(
            shared.iter().any(|byte| *byte != 0),
            "recipient public key has low order"
        );

        let mut file_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(file_key.as_mut());
        let mut wrap_nonce = [0u8; 24];
        let mut file_nonce = [0u8; 24];
        OsRng.fill_bytes(&mut wrap_nonce);
        OsRng.fill_bytes(&mut file_nonce);

        let wrap_key = derive_wrap_key(&shared, &ephemeral_public_key, &recipient.public_key)?;
        let wrap_aad = wrap_aad(recipient, &ephemeral_public_key);
        let wrapped = XChaCha20Poly1305::new((&*wrap_key).into())
            .encrypt(
                XNonce::from_slice(&wrap_nonce),
                Payload {
                    msg: file_key.as_ref(),
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to wrap file key"))?;
        let wrapped_file_key: [u8; 48] = wrapped
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid wrapped file key length"))?;

        let aad = payload_aad(
            recipient,
            &ephemeral_public_key,
            &wrap_nonce,
            &wrapped_file_key,
            &file_nonce,
        );
        let mut plaintext = vault.encode()?;
        let ciphertext = XChaCha20Poly1305::new((&*file_key).into())
            .encrypt(
                XNonce::from_slice(&file_nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt vault"))?;
        plaintext.zeroize();

        Ok(Self {
            recipient: recipient.clone(),
            ephemeral_public_key,
            wrap_nonce,
            wrapped_file_key,
            file_nonce,
            ciphertext,
        })
    }

    pub fn open<F>(&self, agree: F) -> Result<Vault>
    where
        F: FnOnce(&[u8; 32]) -> Result<[u8; 32]>,
    {
        let shared = Zeroizing::new(agree(&self.ephemeral_public_key)?);
        ensure!(
            shared.iter().any(|byte| *byte != 0),
            "YubiKey returned a low-order shared secret"
        );
        let wrap_key = derive_wrap_key(
            &shared,
            &self.ephemeral_public_key,
            &self.recipient.public_key,
        )?;
        let wrap_aad = wrap_aad(&self.recipient, &self.ephemeral_public_key);
        let file_key = Zeroizing::new(
            XChaCha20Poly1305::new((&*wrap_key).into())
                .decrypt(
                    XNonce::from_slice(&self.wrap_nonce),
                    Payload {
                        msg: &self.wrapped_file_key,
                        aad: &wrap_aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("YubiKey cannot unwrap this vault"))?,
        );
        ensure!(file_key.len() == 32, "invalid unwrapped file key length");
        let aad = payload_aad(
            &self.recipient,
            &self.ephemeral_public_key,
            &self.wrap_nonce,
            &self.wrapped_file_key,
            &self.file_nonce,
        );
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(file_key.as_ref())
                .map_err(|_| anyhow::anyhow!("invalid file key"))?
                .decrypt(
                    XNonce::from_slice(&self.file_nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("vault authentication failed"))?,
        );
        Vault::decode(plaintext)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            182usize.saturating_add(self.ciphertext.len()) <= MAX_FILE_SIZE as usize,
            "encoded vault is too large"
        );
        let mut output = Vec::with_capacity(182 + self.ciphertext.len());
        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&self.recipient.serial.to_be_bytes());
        output.push(self.recipient.slot);
        output.extend_from_slice(&self.recipient.public_key);
        output.extend_from_slice(&self.ephemeral_public_key);
        output.extend_from_slice(&self.wrap_nonce);
        output.extend_from_slice(&self.wrapped_file_key);
        output.extend_from_slice(&self.file_nonce);
        output.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_FILE_SIZE,
            "vault is larger than 64 MiB"
        );
        let mut cursor = Cursor::new(bytes);
        ensure!(cursor.take(8)? == MAGIC, "not a nit vault");
        ensure!(cursor.u8()? == VERSION, "unsupported nit vault version");
        let serial = cursor.u32()?;
        let slot = cursor.u8()?;
        let public_key = cursor.array::<32>()?;
        let ephemeral_public_key = cursor.array::<32>()?;
        let wrap_nonce = cursor.array::<24>()?;
        let wrapped_file_key = cursor.array::<48>()?;
        let file_nonce = cursor.array::<24>()?;
        let ciphertext_len = usize::try_from(cursor.u64()?)
            .context("vault ciphertext length does not fit this platform")?;
        ensure!(
            ciphertext_len == cursor.remaining(),
            "invalid vault ciphertext length"
        );
        ensure!(ciphertext_len >= 16, "vault ciphertext is too short");
        let ciphertext = cursor.take(ciphertext_len)?.to_vec();
        Ok(Self {
            recipient: Recipient {
                serial,
                slot,
                public_key,
            },
            ephemeral_public_key,
            wrap_nonce,
            wrapped_file_key,
            file_nonce,
            ciphertext,
        })
    }
}

fn derive_wrap_key(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(WRAP_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    Ok(key)
}

fn wrap_aad(recipient: &Recipient, ephemeral: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(78);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.extend_from_slice(&recipient.serial.to_be_bytes());
    aad.push(recipient.slot);
    aad.extend_from_slice(&recipient.public_key);
    aad.extend_from_slice(ephemeral);
    aad
}

fn payload_aad(
    recipient: &Recipient,
    ephemeral: &[u8; 32],
    wrap_nonce: &[u8; 24],
    wrapped_file_key: &[u8; 48],
    file_nonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = wrap_aad(recipient, ephemeral);
    aad.extend_from_slice(PAYLOAD_AAD_LABEL);
    aad.extend_from_slice(wrap_nonce);
    aad.extend_from_slice(wrapped_file_key);
    aad.extend_from_slice(file_nonce);
    aad
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("vault length overflow")?;
        if end > self.bytes.len() {
            bail!("truncated vault");
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid fixed-width field"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (StaticSecret, Recipient, Vault) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let recipient = Recipient {
            serial: 12345678,
            slot: 0x82,
            public_key: PublicKey::from(&secret).to_bytes(),
        };
        let mut vault = Vault::default();
        vault.insert("API_KEY".into(), "correct horse battery staple".into());
        (secret, recipient, vault)
    }

    #[test]
    fn round_trip() {
        let (secret, recipient, vault) = fixture();
        let bytes = Envelope::seal(&vault, &recipient)
            .unwrap()
            .encode()
            .unwrap();
        let envelope = Envelope::decode(&bytes).unwrap();
        let opened = envelope
            .open(|ephemeral| {
                Ok(secret
                    .diffie_hellman(&PublicKey::from(*ephemeral))
                    .to_bytes())
            })
            .unwrap();
        assert_eq!(opened.get("API_KEY"), Some("correct horse battery staple"));
    }

    #[test]
    fn tampering_is_rejected() {
        let (secret, recipient, vault) = fixture();
        let mut bytes = Envelope::seal(&vault, &recipient)
            .unwrap()
            .encode()
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let envelope = Envelope::decode(&bytes).unwrap();
        assert!(envelope
            .open(|ephemeral| Ok(secret
                .diffie_hellman(&PublicKey::from(*ephemeral))
                .to_bytes()))
            .is_err());
    }

    #[test]
    fn wrong_identity_is_rejected() {
        let (_, recipient, vault) = fixture();
        let wrong = StaticSecret::random_from_rng(OsRng);
        let envelope = Envelope::seal(&vault, &recipient).unwrap();
        assert!(envelope
            .open(|ephemeral| Ok(wrong
                .diffie_hellman(&PublicKey::from(*ephemeral))
                .to_bytes()))
            .is_err());
    }
}
