use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityBackend {
    YubiKey,
    TouchId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceIdentity {
    pub backend: IdentityBackend,
    pub locator: String,
    pub display_name: String,
    pub encryption_public_key: [u8; PUBLIC_KEY_SIZE],
    pub signing_public_key: [u8; PUBLIC_KEY_SIZE],
}

impl DeviceIdentity {
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"git-vault/identity-fingerprint/v1");
        hasher.update(self.signing_public_key);
        hasher.update(self.encryption_public_key);
        hex::encode_upper(&hasher.finalize()[..8])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityState {
    Ready(DeviceIdentity),
    Provisionable,
    Unavailable(String),
}

impl IdentityState {
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Ready(_) | Self::Provisionable)
    }

    pub fn description(&self) -> String {
        match self {
            Self::Ready(identity) => format!("identity {} ready", identity.fingerprint()),
            Self::Provisionable => "identity can be provisioned".into(),
            Self::Unavailable(error) => format!("unavailable: {error}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredIdentity {
    pub backend: IdentityBackend,
    pub locator: String,
    pub display_name: String,
    pub detail: String,
    pub state: IdentityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultTrustRecord {
    pub vault_name: String,
    pub vault_id: [u8; 32],
    pub membership_epoch: u64,
    pub membership_event_hash: [u8; 32],
    pub trusted_trust_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityOperation {
    Sign,
    Agree,
}

pub trait IdentitySession {
    fn identity(&self) -> &DeviceIdentity;
    fn sign(&mut self, message: &[u8; 32]) -> Result<[u8; SIGNATURE_SIZE]>;
    fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]>;

    fn interaction_hint(&self, _operation: IdentityOperation) -> Option<&'static str> {
        None
    }

    fn read_trust_record(&mut self, _vault_name: &str) -> Result<Option<VaultTrustRecord>> {
        Ok(None)
    }

    fn write_trust_record(&mut self, _record: &VaultTrustRecord) -> Result<()> {
        bail!("this identity backend does not yet support hardware trust checkpoints")
    }
}
