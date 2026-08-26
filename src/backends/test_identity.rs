use anyhow::{ensure, Result};
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::{
    DeviceIdentity, DiscoveredIdentity, IdentityBackend, IdentitySession, IdentityState,
};

pub struct TestIdentityBackend {
    device: DeviceIdentity,
    signing: SigningKey,
    encryption: StaticSecret,
}

impl TestIdentityBackend {
    pub fn from_seed(seed: u8, locator: &str) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let encryption = StaticSecret::from([seed.wrapping_add(64); 32]);
        let device = DeviceIdentity {
            backend: "test".into(),
            locator: locator.into(),
            display_name: format!("Test identity {locator}"),
            encryption_public_key: PublicKey::from(&encryption).to_bytes(),
            signing_public_key: signing.verifying_key().to_bytes(),
            certificate: Vec::new(),
        };
        Self {
            device,
            signing,
            encryption,
        }
    }

    pub fn discovered(&self) -> DiscoveredIdentity {
        DiscoveredIdentity {
            backend: "test".into(),
            locator: self.device.locator.clone(),
            display_name: self.device.display_name.clone(),
            detail: "software test identity".into(),
            state: IdentityState::Ready(self.device.clone()),
        }
    }
}

impl IdentityBackend for TestIdentityBackend {
    fn id(&self) -> &'static str {
        "test"
    }

    fn discover(&self) -> Result<Vec<DiscoveredIdentity>> {
        Ok(vec![self.discovered()])
    }

    fn provision(&self, identity: &DiscoveredIdentity) -> Result<DeviceIdentity> {
        ensure!(identity.backend == self.id(), "wrong test backend");
        Ok(self.device.clone())
    }

    fn open(&self, identity: &DiscoveredIdentity) -> Result<Box<dyn IdentitySession>> {
        ensure!(identity.backend == self.id(), "wrong test backend");
        Ok(Box::new(TestIdentitySession {
            device: self.device.clone(),
            signing: self.signing.clone(),
            encryption: self.encryption.clone(),
        }))
    }
}

pub struct TestIdentitySession {
    device: DeviceIdentity,
    signing: SigningKey,
    encryption: StaticSecret,
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
}
