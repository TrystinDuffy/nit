use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{ensure, Result};
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::{DeviceIdentity, IdentityBackend, IdentitySession, VaultTrustRecord};

pub struct TestIdentityBackend {
    device: DeviceIdentity,
    signing: SigningKey,
    encryption: StaticSecret,
    trust_records: Arc<Mutex<BTreeMap<String, VaultTrustRecord>>>,
}

impl TestIdentityBackend {
    pub fn from_seed(seed: u8, locator: &str) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let encryption = StaticSecret::from([seed.wrapping_add(64); 32]);
        Self {
            device: DeviceIdentity {
                backend: IdentityBackend::TouchId,
                locator: locator.into(),
                display_name: format!("Test identity {locator}"),
                encryption_public_key: PublicKey::from(&encryption).to_bytes(),
                signing_public_key: signing.verifying_key().to_bytes(),
            },
            signing,
            encryption,
            trust_records: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn device(&self) -> DeviceIdentity {
        self.device.clone()
    }

    pub fn open(&self) -> Box<dyn IdentitySession> {
        Box::new(TestIdentitySession {
            device: self.device.clone(),
            signing: self.signing.clone(),
            encryption: self.encryption.clone(),
            trust_records: Arc::clone(&self.trust_records),
        })
    }
}

struct TestIdentitySession {
    device: DeviceIdentity,
    signing: SigningKey,
    encryption: StaticSecret,
    trust_records: Arc<Mutex<BTreeMap<String, VaultTrustRecord>>>,
}

impl IdentitySession for TestIdentitySession {
    fn identity(&self) -> &DeviceIdentity {
        &self.device
    }

    fn sign(&mut self, message: &[u8; 32]) -> Result<[u8; 64]> {
        Ok(self.signing.sign(message).to_bytes())
    }

    fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(self
            .encryption
            .diffie_hellman(&PublicKey::from(*peer_public_key))
            .to_bytes())
    }

    fn read_trust_record(&mut self, vault_name: &str) -> Result<Option<VaultTrustRecord>> {
        Ok(self.trust_records.lock().unwrap().get(vault_name).cloned())
    }

    fn write_trust_record(&mut self, record: &VaultTrustRecord) -> Result<()> {
        let mut records = self.trust_records.lock().unwrap();
        if let Some(existing) = records.get(&record.vault_name) {
            ensure!(
                record.membership_epoch >= existing.membership_epoch,
                "test checkpoint rollback"
            );
        }
        records.insert(record.vault_name.clone(), record.clone());
        Ok(())
    }
}
