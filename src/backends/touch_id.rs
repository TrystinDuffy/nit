use anyhow::{ensure, Context, Result};
use block2::RcBlock;
use ed25519_dalek::{Signer, SigningKey};
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use rand_core::{OsRng, RngCore};
use security_framework::passwords::{generic_password, set_generic_password, PasswordOptions};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::identity::{
    DeviceIdentity, DiscoveredIdentity, IdentityBackend, IdentitySession, IdentityState,
    VaultTrustRecord,
};

const SERVICE: &str = "com.git-vault.touch-id";
const SECRET_ACCOUNT: &str = "identity-v1";
const PUBLIC_ACCOUNT: &str = "identity-public-v1";
const LOCATOR: &str = "touchid";
const SECRET_MAGIC: &[u8; 8] = b"GVTID001";
const PUBLIC_MAGIC: &[u8; 8] = b"GVTIDPUB";
const CHECKPOINT_MAGIC: &[u8; 8] = b"GVTIDCHK";
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

pub fn discover() -> Result<Vec<DiscoveredIdentity>> {
    let state = match read_item(PUBLIC_ACCOUNT) {
        Ok(Some(bytes)) => match decode_public(&bytes) {
            Ok(device) => IdentityState::Ready(device),
            Err(error) => IdentityState::Unavailable(error.to_string()),
        },
        Ok(None) => IdentityState::Provisionable,
        Err(error) => IdentityState::Unavailable(error.to_string()),
    };
    Ok(vec![DiscoveredIdentity {
        backend: IdentityBackend::TouchId,
        locator: LOCATOR.into(),
        display_name: "Mac Touch ID".into(),
        detail: "Touch ID-authenticated Keychain identity (private keys enter process memory)"
            .into(),
        state,
    }])
}

pub fn provision(identity: &DiscoveredIdentity) -> Result<DeviceIdentity> {
    ensure!(
        identity.backend == IdentityBackend::TouchId,
        "selected identity is not Mac Touch ID"
    );
    if let IdentityState::Ready(device) = &identity.state {
        return Ok(device.clone());
    }
    ensure!(
        matches!(identity.state, IdentityState::Provisionable),
        "Mac Touch ID identity is unavailable: {}",
        identity.state.description()
    );

    let mut generated = Zeroizing::new([0u8; 64]);
    OsRng.fill_bytes(&mut *generated);
    write_secret(&generated)?;
    let secret = read_secret()?.context("Touch ID did not unlock the new identity")?;
    ensure!(*secret == *generated, "Touch ID identity reread mismatch");
    let device = device_from_secret(&secret);
    set_generic_password(SERVICE, PUBLIC_ACCOUNT, &encode_public(&device))
        .context("cannot store Mac Touch ID public identity")?;
    Ok(device)
}

pub fn open(identity: &DiscoveredIdentity) -> Result<Box<dyn IdentitySession>> {
    let IdentityState::Ready(expected) = &identity.state else {
        anyhow::bail!("Mac Touch ID identity is not provisioned");
    };
    let secret = read_secret()?.context("Mac Touch ID private identity is absent")?;
    let device = device_from_secret(&secret);
    ensure!(
        &device == expected,
        "Mac Touch ID private identity does not match its public metadata"
    );
    Ok(Box::new(TouchIdSession {
        device,
        signing: SigningKey::from_bytes(secret[..32].try_into().expect("length checked")),
        encryption: StaticSecret::from(
            <[u8; 32]>::try_from(&secret[32..]).expect("length checked"),
        ),
    }))
}

struct TouchIdSession {
    device: DeviceIdentity,
    signing: SigningKey,
    encryption: StaticSecret,
}

impl IdentitySession for TouchIdSession {
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
        read_item(&checkpoint_account(vault_name))?
            .map(|bytes| decode_checkpoint(vault_name, &bytes))
            .transpose()
    }

    fn write_trust_record(&mut self, record: &VaultTrustRecord) -> Result<()> {
        if let Some(existing) = self.read_trust_record(&record.vault_name)? {
            ensure!(
                record.membership_epoch >= existing.membership_epoch,
                "Touch ID checkpoint rollback"
            );
        }
        let account = checkpoint_account(&record.vault_name);
        let encoded = encode_checkpoint(record);
        set_generic_password(SERVICE, &account, &encoded)
            .context("cannot write Mac Touch ID checkpoint")?;
        ensure!(
            read_item(&account)?.as_deref() == Some(encoded.as_slice()),
            "Mac Touch ID checkpoint reread mismatch"
        );
        Ok(())
    }
}

fn read_secret() -> Result<Option<Zeroizing<[u8; 64]>>> {
    authenticate()?;
    let Some(mut encoded) = read_item(SECRET_ACCOUNT)? else {
        return Ok(None);
    };
    let result = (|| {
        ensure!(
            encoded.len() == 72 && &encoded[..8] == SECRET_MAGIC,
            "invalid Mac Touch ID private identity"
        );
        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(&encoded[8..]);
        Ok(Some(secret))
    })();
    encoded.zeroize();
    result
}

fn write_secret(secret: &[u8; 64]) -> Result<()> {
    let mut encoded = Zeroizing::new(SECRET_MAGIC.to_vec());
    encoded.extend_from_slice(secret);
    set_generic_password(SERVICE, SECRET_ACCOUNT, &encoded)
        .context("cannot store private identity in the login Keychain")
}

fn authenticate() -> Result<()> {
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
        .map_err(|error| anyhow::anyhow!("Touch ID is unavailable: {error}"))?;

    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reply = RcBlock::new(move |success: Bool, _: *mut NSError| {
        let _ = send.send(success.as_bool());
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &NSString::from_str("unlock your git-vault identity"),
            &reply,
        );
    }
    ensure!(
        receive
            .recv()
            .context("Touch ID response was interrupted")?,
        "Touch ID authentication failed"
    );
    Ok(())
}

fn read_item(account: &str) -> Result<Option<Vec<u8>>> {
    match generic_password(PasswordOptions::new_generic_password(SERVICE, account)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot read Keychain item {account}")),
    }
}

fn device_from_secret(secret: &[u8; 64]) -> DeviceIdentity {
    let signing = SigningKey::from_bytes(secret[..32].try_into().expect("length checked"));
    let encryption =
        StaticSecret::from(<[u8; 32]>::try_from(&secret[32..]).expect("length checked"));
    DeviceIdentity {
        backend: IdentityBackend::TouchId,
        locator: LOCATOR.into(),
        display_name: "Mac Touch ID".into(),
        encryption_public_key: PublicKey::from(&encryption).to_bytes(),
        signing_public_key: signing.verifying_key().to_bytes(),
    }
}

fn encode_public(device: &DeviceIdentity) -> Vec<u8> {
    [
        PUBLIC_MAGIC.as_slice(),
        &device.encryption_public_key,
        &device.signing_public_key,
    ]
    .concat()
}

fn decode_public(bytes: &[u8]) -> Result<DeviceIdentity> {
    ensure!(
        bytes.len() == 72 && &bytes[..8] == PUBLIC_MAGIC,
        "invalid Mac Touch ID public identity"
    );
    Ok(DeviceIdentity {
        backend: IdentityBackend::TouchId,
        locator: LOCATOR.into(),
        display_name: "Mac Touch ID".into(),
        encryption_public_key: bytes[8..40].try_into().expect("length checked"),
        signing_public_key: bytes[40..72].try_into().expect("length checked"),
    })
}

fn checkpoint_account(vault_name: &str) -> String {
    format!("checkpoint:{vault_name}")
}

fn encode_checkpoint(record: &VaultTrustRecord) -> Vec<u8> {
    [
        CHECKPOINT_MAGIC.as_slice(),
        &record.vault_id,
        &record.membership_epoch.to_be_bytes(),
        &record.membership_event_hash,
        &record.trusted_trust_hash,
    ]
    .concat()
}

fn decode_checkpoint(vault_name: &str, bytes: &[u8]) -> Result<VaultTrustRecord> {
    ensure!(
        bytes.len() == 112 && &bytes[..8] == CHECKPOINT_MAGIC,
        "invalid Mac Touch ID checkpoint"
    );
    Ok(VaultTrustRecord {
        vault_name: vault_name.into(),
        vault_id: bytes[8..40].try_into().expect("length checked"),
        membership_epoch: u64::from_be_bytes(bytes[40..48].try_into().expect("length checked")),
        membership_event_hash: bytes[48..80].try_into().expect("length checked"),
        trusted_trust_hash: bytes[80..112].try_into().expect("length checked"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identity_and_checkpoint_codecs_round_trip() {
        let device = device_from_secret(&[7; 64]);
        assert_eq!(decode_public(&encode_public(&device)).unwrap(), device);
        let record = VaultTrustRecord {
            vault_name: "test".into(),
            vault_id: [1; 32],
            membership_epoch: 2,
            membership_event_hash: [3; 32],
            trusted_trust_hash: [4; 32],
        };
        assert_eq!(
            decode_checkpoint("test", &encode_checkpoint(&record)).unwrap(),
            record
        );
    }
}
