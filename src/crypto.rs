use std::collections::BTreeMap;

use anyhow::{bail, ensure, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    event::{
        EncryptedSnapshot, MemberIdentity, ValueType, VaultId, WrappedEpochKey, MAX_KEY_LEN,
        MAX_VALUE_SIZE,
    },
    identity::IdentitySession,
};

const WRAP_KDF_DOMAIN: &[u8] = b"git-vault/epoch-wrap-kdf/v1";
const WRAP_AAD_DOMAIN: &[u8] = b"git-vault/epoch-wrap-aad/v1";
const SNAPSHOT_AAD_DOMAIN: &[u8] = b"git-vault/snapshot-aad/v1";
const MUTATION_AAD_DOMAIN: &[u8] = b"git-vault/mutation-aad/v1";
const SNAPSHOT_MAGIC: &[u8; 8] = b"GVSNP001";
const MUTATION_MAGIC: &[u8; 8] = b"GVMUT001";

pub type EpochKey = Zeroizing<[u8; 32]>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecryptedMutation {
    Put { key: String, value: VaultValue },
    Delete { key: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultValue {
    Text(String),
    Number(String),
    Boolean(bool),
    Bytes(Vec<u8>),
}

impl VaultValue {
    pub fn value_type(&self) -> ValueType {
        match self {
            Self::Text(_) => ValueType::Text,
            Self::Number(_) => ValueType::Number,
            Self::Boolean(_) => ValueType::Boolean,
            Self::Bytes(_) => ValueType::Bytes,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(value) | Self::Number(value) => value.as_bytes().to_vec(),
            Self::Boolean(value) => vec![u8::from(*value)],
            Self::Bytes(value) => value.clone(),
        }
    }

    pub fn from_bytes(value_type: ValueType, bytes: Vec<u8>) -> Result<Self> {
        ensure!(bytes.len() <= MAX_VALUE_SIZE, "secret value is too large");
        match value_type {
            ValueType::Text => Ok(Self::Text(
                String::from_utf8(bytes).context("text value is not UTF-8")?,
            )),
            ValueType::Number => {
                let value = String::from_utf8(bytes).context("number value is not UTF-8")?;
                validate_number(&value)?;
                Ok(Self::Number(value))
            }
            ValueType::Boolean => match bytes.as_slice() {
                [0] => Ok(Self::Boolean(false)),
                [1] => Ok(Self::Boolean(true)),
                _ => bail!("invalid Boolean encoding"),
            },
            ValueType::Bytes => Ok(Self::Bytes(bytes)),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Text(value) | Self::Number(value) => value.clone(),
            Self::Boolean(value) => value.to_string(),
            Self::Bytes(value) => hex::encode(value),
        }
    }

    pub fn parse(value_type: ValueType, input: String) -> Result<Self> {
        match value_type {
            ValueType::Text => Ok(Self::Text(input)),
            ValueType::Number => {
                validate_number(&input)?;
                Ok(Self::Number(input))
            }
            ValueType::Boolean => match input.as_str() {
                "true" => Ok(Self::Boolean(true)),
                "false" => Ok(Self::Boolean(false)),
                _ => bail!("Boolean values must be true or false"),
            },
            ValueType::Bytes => Ok(Self::Bytes(
                hex::decode(&input).context("Bytes values must be hexadecimal")?,
            )),
        }
    }
}

impl Drop for VaultValue {
    fn drop(&mut self) {
        match self {
            Self::Text(value) | Self::Number(value) => value.zeroize(),
            Self::Bytes(value) => value.zeroize(),
            Self::Boolean(value) => *value = false,
        }
    }
}

pub fn random_epoch_key() -> EpochKey {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

pub fn wrap_epoch_key(
    vault_id: &VaultId,
    epoch_number: u64,
    recipient: &MemberIdentity,
    epoch_key: &[u8; 32],
) -> Result<WrappedEpochKey> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = Zeroizing::new(
        ephemeral_secret
            .diffie_hellman(&PublicKey::from(recipient.encryption_public_key))
            .to_bytes(),
    );
    reject_zero_shared(&shared)?;
    let wrapping_key = derive_wrapping_key(
        vault_id,
        epoch_number,
        recipient,
        &ephemeral_public_key,
        &shared,
    )?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = wrap_aad(vault_id, epoch_number, recipient, &ephemeral_public_key);
    let ciphertext = encrypt(&wrapping_key, &nonce, epoch_key, &aad)?;
    Ok(WrappedEpochKey {
        ephemeral_public_key,
        nonce,
        ciphertext,
    })
}

pub fn unwrap_epoch_key(
    vault_id: &VaultId,
    epoch_number: u64,
    recipient: &MemberIdentity,
    wrapped: &WrappedEpochKey,
    session: &mut dyn IdentitySession,
) -> Result<EpochKey> {
    ensure!(
        session.identity().encryption_public_key == recipient.encryption_public_key
            && session.identity().signing_public_key == recipient.signing_public_key,
        "unlocked identity does not match epoch member"
    );
    let shared = Zeroizing::new(session.agree(&wrapped.ephemeral_public_key)?);
    reject_zero_shared(&shared)?;
    let wrapping_key = derive_wrapping_key(
        vault_id,
        epoch_number,
        recipient,
        &wrapped.ephemeral_public_key,
        &shared,
    )?;
    let aad = wrap_aad(
        vault_id,
        epoch_number,
        recipient,
        &wrapped.ephemeral_public_key,
    );
    let mut plaintext = decrypt(&wrapping_key, &wrapped.nonce, &wrapped.ciphertext, &aad)
        .context("cannot unwrap membership epoch key")?;
    ensure!(plaintext.len() == 32, "invalid unwrapped epoch key size");
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

pub fn encrypt_snapshot(
    vault_id: &VaultId,
    epoch_number: u64,
    values: &BTreeMap<String, VaultValue>,
    epoch_key: &[u8; 32],
) -> Result<EncryptedSnapshot> {
    let mut plaintext = Zeroizing::new(encode_values(values)?);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = snapshot_aad(vault_id, epoch_number);
    let ciphertext = encrypt(epoch_key, &nonce, &plaintext, &aad)?;
    plaintext.zeroize();
    Ok(EncryptedSnapshot { nonce, ciphertext })
}

pub fn decrypt_snapshot(
    vault_id: &VaultId,
    epoch_number: u64,
    snapshot: &EncryptedSnapshot,
    epoch_key: &[u8; 32],
) -> Result<BTreeMap<String, VaultValue>> {
    let mut plaintext = Zeroizing::new(
        decrypt(
            epoch_key,
            &snapshot.nonce,
            &snapshot.ciphertext,
            &snapshot_aad(vault_id, epoch_number),
        )
        .context("cannot decrypt membership snapshot")?,
    );
    let values = decode_values(&plaintext)?;
    plaintext.zeroize();
    Ok(values)
}

pub fn encrypt_mutation(
    vault_id: &VaultId,
    epoch_number: u64,
    mutation: &DecryptedMutation,
    epoch_key: &[u8; 32],
) -> Result<([u8; 12], Vec<u8>)> {
    let mut plaintext = Zeroizing::new(encode_mutation(mutation)?);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt(
        epoch_key,
        &nonce,
        &plaintext,
        &mutation_aad(vault_id, epoch_number),
    )?;
    plaintext.zeroize();
    Ok((nonce, ciphertext))
}

pub fn decrypt_mutation(
    vault_id: &VaultId,
    epoch_number: u64,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    epoch_key: &[u8; 32],
) -> Result<DecryptedMutation> {
    let mut plaintext = Zeroizing::new(
        decrypt(
            epoch_key,
            nonce,
            ciphertext,
            &mutation_aad(vault_id, epoch_number),
        )
        .context("cannot decrypt trusted mutation event")?,
    );
    let mutation = decode_mutation(&plaintext)?;
    plaintext.zeroize();
    Ok(mutation)
}

fn encode_mutation(mutation: &DecryptedMutation) -> Result<Vec<u8>> {
    let mut output = MUTATION_MAGIC.to_vec();
    match mutation {
        DecryptedMutation::Put { key, value } => {
            validate_secret_key(key)?;
            output.push(1);
            put_sized_bytes(&mut output, key.as_bytes())?;
            output.push(encode_value_type(value.value_type()));
            put_sized_bytes(&mut output, &value.as_bytes())?;
        }
        DecryptedMutation::Delete { key } => {
            validate_secret_key(key)?;
            output.push(2);
            put_sized_bytes(&mut output, key.as_bytes())?;
        }
    }
    ensure!(
        output.len() <= MAX_VALUE_SIZE + MAX_KEY_LEN + 32,
        "mutation plaintext is too large"
    );
    Ok(output)
}

fn decode_mutation(bytes: &[u8]) -> Result<DecryptedMutation> {
    ensure!(bytes.len() >= 9, "truncated mutation plaintext");
    ensure!(
        &bytes[..8] == MUTATION_MAGIC,
        "invalid mutation plaintext magic"
    );
    let mut offset = 9usize;
    let operation = bytes[8];
    let key = String::from_utf8(take_sized_bytes(bytes, &mut offset, MAX_KEY_LEN)?.to_vec())
        .context("mutation key is not UTF-8")?;
    validate_secret_key(&key)?;
    let mutation = match operation {
        1 => {
            let value_type = decode_value_type(*bytes.get(offset).context("missing value type")?)?;
            offset += 1;
            let value = VaultValue::from_bytes(
                value_type,
                take_sized_bytes(bytes, &mut offset, MAX_VALUE_SIZE)?.to_vec(),
            )?;
            DecryptedMutation::Put { key, value }
        }
        2 => DecryptedMutation::Delete { key },
        _ => bail!("unknown mutation operation {operation}"),
    };
    ensure!(offset == bytes.len(), "trailing mutation plaintext data");
    Ok(mutation)
}

fn validate_secret_key(key: &str) -> Result<()> {
    ensure!(
        !key.is_empty() && key.len() <= MAX_KEY_LEN && !key.contains('\0'),
        "invalid secret key"
    );
    Ok(())
}

fn encode_value_type(value_type: ValueType) -> u8 {
    match value_type {
        ValueType::Text => 1,
        ValueType::Number => 2,
        ValueType::Boolean => 3,
        ValueType::Bytes => 4,
    }
}

fn decode_value_type(value: u8) -> Result<ValueType> {
    match value {
        1 => Ok(ValueType::Text),
        2 => Ok(ValueType::Number),
        3 => Ok(ValueType::Boolean),
        4 => Ok(ValueType::Bytes),
        _ => bail!("unknown mutation value type {value}"),
    }
}

fn put_sized_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("mutation field is too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn take_sized_bytes<'a>(bytes: &'a [u8], offset: &mut usize, limit: usize) -> Result<&'a [u8]> {
    let length_end = offset.checked_add(4).context("mutation length overflow")?;
    let length_bytes = bytes
        .get(*offset..length_end)
        .context("truncated mutation length")?;
    *offset = length_end;
    let length = u32::from_be_bytes(length_bytes.try_into().expect("length checked")) as usize;
    ensure!(length <= limit, "mutation field is too large");
    let end = offset
        .checked_add(length)
        .context("mutation length overflow")?;
    let field = bytes
        .get(*offset..end)
        .context("truncated mutation field")?;
    *offset = end;
    Ok(field)
}

fn derive_wrapping_key(
    vault_id: &VaultId,
    epoch_number: u64,
    recipient: &MemberIdentity,
    ephemeral_public_key: &[u8; 32],
    shared: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = Vec::new();
    salt.extend_from_slice(vault_id);
    salt.extend_from_slice(&epoch_number.to_be_bytes());
    salt.extend_from_slice(&recipient.signing_public_key);
    salt.extend_from_slice(&recipient.encryption_public_key);
    salt.extend_from_slice(ephemeral_public_key);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(WRAP_KDF_DOMAIN, key.as_mut())
        .map_err(|_| anyhow::anyhow!("cannot derive epoch wrapping key"))?;
    Ok(key)
}

fn wrap_aad(
    vault_id: &VaultId,
    epoch_number: u64,
    recipient: &MemberIdentity,
    ephemeral_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&epoch_number.to_be_bytes());
    aad.extend_from_slice(&recipient.signing_public_key);
    aad.extend_from_slice(&recipient.encryption_public_key);
    aad.extend_from_slice(ephemeral_public_key);
    aad
}

fn snapshot_aad(vault_id: &VaultId, epoch_number: u64) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(SNAPSHOT_AAD_DOMAIN);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&epoch_number.to_be_bytes());
    aad
}

fn mutation_aad(vault_id: &VaultId, epoch_number: u64) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(MUTATION_AAD_DOMAIN);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&epoch_number.to_be_bytes());
    aad
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("authenticated encryption failed"))
}

fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("authenticated decryption failed"))
}

fn reject_zero_shared(shared: &[u8; 32]) -> Result<()> {
    let accumulated = shared.iter().fold(0u8, |value, byte| value | byte);
    ensure!(
        !bool::from(accumulated.ct_eq(&0)),
        "X25519 produced an invalid all-zero shared secret"
    );
    Ok(())
}

fn validate_number(value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "number cannot be empty");
    let parsed = value.parse::<f64>().context("invalid number")?;
    ensure!(parsed.is_finite(), "number must be finite");
    Ok(())
}

fn encode_values(values: &BTreeMap<String, VaultValue>) -> Result<Vec<u8>> {
    ensure!(values.len() <= 10_000, "too many secrets in snapshot");
    let mut output = SNAPSHOT_MAGIC.to_vec();
    output.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for (key, value) in values {
        ensure!(
            !key.is_empty() && key.len() <= MAX_KEY_LEN,
            "invalid secret key"
        );
        let key_len = u32::try_from(key.len()).context("secret key is too large")?;
        output.extend_from_slice(&key_len.to_be_bytes());
        output.extend_from_slice(key.as_bytes());
        output.push(match value.value_type() {
            ValueType::Text => 1,
            ValueType::Number => 2,
            ValueType::Boolean => 3,
            ValueType::Bytes => 4,
        });
        let mut bytes = Zeroizing::new(value.as_bytes());
        ensure!(bytes.len() <= MAX_VALUE_SIZE, "secret value is too large");
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(&bytes);
        bytes.zeroize();
    }
    ensure!(output.len() <= MAX_VALUE_SIZE, "snapshot is too large");
    Ok(output)
}

fn decode_values(bytes: &[u8]) -> Result<BTreeMap<String, VaultValue>> {
    let mut decoder = SnapshotDecoder::new(bytes);
    ensure!(decoder.take(8)? == SNAPSHOT_MAGIC, "invalid snapshot magic");
    let count = decoder.u32()? as usize;
    ensure!(count <= 10_000, "too many secrets in snapshot");
    let mut values = BTreeMap::new();
    for _ in 0..count {
        let key_len = decoder.u32()? as usize;
        ensure!(
            key_len > 0 && key_len <= MAX_KEY_LEN,
            "invalid secret key size"
        );
        let key = String::from_utf8(decoder.take(key_len)?.to_vec())
            .context("secret key is not UTF-8")?;
        let value_type = match decoder.u8()? {
            1 => ValueType::Text,
            2 => ValueType::Number,
            3 => ValueType::Boolean,
            4 => ValueType::Bytes,
            value => bail!("unknown snapshot value type {value}"),
        };
        let value_len = decoder.u32()? as usize;
        ensure!(value_len <= MAX_VALUE_SIZE, "snapshot value is too large");
        let value = VaultValue::from_bytes(value_type, decoder.take(value_len)?.to_vec())?;
        ensure!(
            values.insert(key, value).is_none(),
            "duplicate key in snapshot"
        );
    }
    ensure!(decoder.is_empty(), "trailing data in encrypted snapshot");
    Ok(values)
}

struct SnapshotDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("snapshot length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated snapshot")?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DeviceIdentity, IdentityBackend};

    struct SoftwareSession {
        identity: DeviceIdentity,
        encryption_secret: StaticSecret,
    }

    impl IdentitySession for SoftwareSession {
        fn identity(&self) -> &DeviceIdentity {
            &self.identity
        }

        fn sign(&mut self, _message: &[u8; 32]) -> Result<[u8; 64]> {
            unreachable!()
        }

        fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
            Ok(self
                .encryption_secret
                .diffie_hellman(&PublicKey::from(*peer_public_key))
                .to_bytes())
        }
    }

    #[test]
    fn epoch_wrap_snapshot_and_typed_values_round_trip() {
        let secret = StaticSecret::from([9; 32]);
        let encryption_public_key = PublicKey::from(&secret).to_bytes();
        let member = MemberIdentity {
            name: "Alice".into(),
            signing_public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
            encryption_public_key,
        };
        let device = DeviceIdentity {
            backend: IdentityBackend::TouchId,
            locator: "alice".into(),
            display_name: "Alice".into(),
            encryption_public_key,
            signing_public_key: member.signing_public_key,
        };
        let epoch_key = random_epoch_key();
        let wrapped = wrap_epoch_key(&[1; 32], 1, &member, &epoch_key).unwrap();
        let mut session = SoftwareSession {
            identity: device,
            encryption_secret: secret,
        };
        let opened = unwrap_epoch_key(&[1; 32], 1, &member, &wrapped, &mut session).unwrap();
        assert_eq!(&*opened, &*epoch_key);

        let values = BTreeMap::from([
            ("text".into(), VaultValue::Text("hello".into())),
            ("number".into(), VaultValue::Number("42.5".into())),
            ("boolean".into(), VaultValue::Boolean(true)),
            ("bytes".into(), VaultValue::Bytes(vec![0, 1, 2])),
        ]);
        let snapshot = encrypt_snapshot(&[1; 32], 1, &values, &epoch_key).unwrap();
        assert_eq!(
            decrypt_snapshot(&[1; 32], 1, &snapshot, &epoch_key).unwrap(),
            values
        );

        let mutation = DecryptedMutation::Put {
            key: "AWS_ROOT_PASSWORD".into(),
            value: VaultValue::Text("hidden".into()),
        };
        let (nonce, ciphertext) = encrypt_mutation(&[1; 32], 1, &mutation, &epoch_key).unwrap();
        assert!(!ciphertext
            .windows("AWS_ROOT_PASSWORD".len())
            .any(|window| window == b"AWS_ROOT_PASSWORD"));
        assert_eq!(
            decrypt_mutation(&[1; 32], 1, &nonce, &ciphertext, &epoch_key).unwrap(),
            mutation
        );
    }
}
