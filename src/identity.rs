use std::{cell::RefCell, str::FromStr};

use age::DecryptError;
use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, hkdf as age_hkdf},
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use bech32::{Bech32, Hrp};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const AGE_X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRecipient {
    pub name: String,
    pub backend: String,
    pub locator: String,
    pub age_recipient: String,
}

impl AuthorizedRecipient {
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.age_recipient.as_bytes());
        hex::encode_upper(&digest[..8])
    }

    pub fn same_identity(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.locator == other.locator
            && self.age_recipient == other.age_recipient
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityState {
    Ready { age_recipient: String },
    Provisionable,
    Unavailable(String),
}

impl IdentityState {
    pub fn is_provisionable(&self) -> bool {
        matches!(self, Self::Ready { .. } | Self::Provisionable)
    }

    pub fn description(&self) -> String {
        match self {
            Self::Ready { .. } => "identity ready".into(),
            Self::Provisionable => "identity can be provisioned".into(),
            Self::Unavailable(error) => format!("unavailable: {error}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredIdentity {
    pub backend: String,
    pub locator: String,
    pub display_name: String,
    pub detail: String,
    pub state: IdentityState,
}

impl DiscoveredIdentity {
    pub fn selector(&self) -> String {
        format!("{}:{}", self.backend, self.locator)
    }
}

pub trait IdentityBackend {
    fn id(&self) -> &'static str;
    fn discover(&self) -> Result<Vec<DiscoveredIdentity>>;
    fn matches(&self, identity: &DiscoveredIdentity, recipient: &AuthorizedRecipient) -> bool;
    fn provision(
        &self,
        identity: &DiscoveredIdentity,
        friendly_name: String,
    ) -> Result<AuthorizedRecipient>;
    fn unlock(
        &self,
        identity: &DiscoveredIdentity,
        recipient: &AuthorizedRecipient,
        stanza_index: usize,
    ) -> Result<Box<dyn UnlockIdentity>>;
}

pub trait UnlockIdentity {
    fn age_identity(&self) -> &dyn age::Identity;
    fn take_error(&self) -> Option<anyhow::Error> {
        None
    }
}

pub trait X25519KeyAgreement {
    fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]>;
    fn prompt(&self) -> &str;
}

pub struct X25519AgeIdentity {
    agreement: RefCell<Box<dyn X25519KeyAgreement>>,
    recipient_public_key: [u8; 32],
    stanza_index: usize,
    error: RefCell<Option<anyhow::Error>>,
}

impl X25519AgeIdentity {
    pub fn new(
        agreement: Box<dyn X25519KeyAgreement>,
        recipient_public_key: [u8; 32],
        stanza_index: usize,
    ) -> Self {
        Self {
            agreement: RefCell::new(agreement),
            recipient_public_key,
            stanza_index,
            error: RefCell::new(None),
        }
    }
}

impl UnlockIdentity for X25519AgeIdentity {
    fn age_identity(&self) -> &dyn age::Identity {
        self
    }

    fn take_error(&self) -> Option<anyhow::Error> {
        self.error.borrow_mut().take()
    }
}

impl age::Identity for X25519AgeIdentity {
    fn unwrap_stanza(&self, _stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        None
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        let stanza = stanzas
            .iter()
            .filter(|stanza| stanza.tag == "X25519")
            .nth(self.stanza_index)?;
        let ephemeral = match parse_x25519_stanza(stanza) {
            Ok(ephemeral) => ephemeral,
            Err(error) => return Some(Err(error)),
        };
        eprintln!("{}", self.agreement.borrow().prompt());
        let shared = match self.agreement.borrow_mut().agree(&ephemeral) {
            Ok(shared) => Zeroizing::new(shared),
            Err(error) => {
                *self.error.borrow_mut() = Some(error);
                return Some(Err(DecryptError::KeyDecryptionFailed));
            }
        };
        if bool::from(shared.iter().fold(0, |acc, byte| acc | byte).ct_eq(&0)) {
            return Some(Err(DecryptError::InvalidHeader));
        }
        unwrap_age_file_key(stanza, &ephemeral, &self.recipient_public_key, &shared).map(Ok)
    }
}

pub fn encode_age_recipient(public_key: &[u8; 32]) -> Result<String> {
    let hrp = Hrp::parse("age").context("invalid age HRP")?;
    bech32::encode::<Bech32>(hrp, public_key).context("cannot encode age recipient")
}

pub fn decode_age_recipient(recipient: &str) -> Result<[u8; 32]> {
    age::x25519::Recipient::from_str(recipient)
        .map_err(|error| anyhow::anyhow!("invalid age recipient: {error}"))?;
    let (hrp, bytes) = bech32::decode(recipient).context("invalid age recipient encoding")?;
    anyhow::ensure!(hrp == Hrp::parse("age")?, "invalid age recipient prefix");
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid age recipient public key length"))
}

fn parse_x25519_stanza(stanza: &Stanza) -> Result<[u8; 32], DecryptError> {
    if stanza.tag != "X25519" || stanza.body.len() != FILE_KEY_BYTES + 16 {
        return Err(DecryptError::InvalidHeader);
    }
    match stanza.args.as_slice() {
        [argument] => match STANDARD_NO_PAD.decode(argument) {
            Ok(bytes) if bytes.len() == 32 => {
                bytes.try_into().map_err(|_| DecryptError::InvalidHeader)
            }
            _ => Err(DecryptError::InvalidHeader),
        },
        _ => Err(DecryptError::InvalidHeader),
    }
}

fn unwrap_age_file_key(
    stanza: &Stanza,
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
    shared: &[u8; 32],
) -> Option<FileKey> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let wrapping_key = age_hkdf(&salt, AGE_X25519_LABEL, shared);
    aead_decrypt(&wrapping_key, FILE_KEY_BYTES, &stanza.body)
        .ok()
        .map(|mut plaintext| {
            let key = FileKey::init_with_mut(|file_key| file_key.copy_from_slice(&plaintext));
            plaintext.zeroize();
            key
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::Recipient as _;
    use age_core::secrecy::ExposeSecret;
    use rand_core::OsRng;

    #[test]
    fn hardware_adapter_matches_standard_age_x25519() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let recipient = encode_age_recipient(&public)
            .unwrap()
            .parse::<age::x25519::Recipient>()
            .unwrap();
        let expected = FileKey::new(Box::new([9u8; FILE_KEY_BYTES]));
        let (stanzas, _) = recipient.wrap_file_key(&expected).unwrap();
        let ephemeral = parse_x25519_stanza(&stanzas[0]).unwrap();
        let shared = secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral))
            .to_bytes();
        let opened = unwrap_age_file_key(&stanzas[0], &ephemeral, &public, &shared).unwrap();
        assert_eq!(opened.expose_secret(), expected.expose_secret());
    }

    #[test]
    fn age_recipient_encoding_round_trips() {
        let key = [7u8; 32];
        let encoded = encode_age_recipient(&key).unwrap();
        assert_eq!(decode_age_recipient(&encoded).unwrap(), key);
    }
}
