use std::{
    collections::BTreeMap,
    io::{Read, Write},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use age::{Decryptor, Encryptor};
use anyhow::{bail, ensure, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::identity::{AuthorizedRecipient, UnlockIdentity};

const CONTAINER_MAGIC: &[u8; 8] = b"NITVLT03";
const PAYLOAD_MAGIC: &[u8; 8] = b"NITPLD03";
const REQUEST_MAGIC: &[u8; 8] = b"NITREQ02";
const INVITE_BINDING_LABEL: &[u8] = b"nit/invite/v2/binding";
const INVITE_REQUEST_LABEL: &[u8] = b"nit/invite/v2/request";
const MAX_SECRETS: usize = 10_000;
const MAX_NAME_LEN: usize = 1_024;
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 64;
const MAX_INVITATIONS: usize = 32;
const MAX_REQUESTS: usize = 64;
const MAX_REQUEST_SIZE: usize = 64 * 1024;
const MAX_FRIENDLY_NAME: usize = 128;
const MAX_BACKEND_ID: usize = 64;
const MAX_LOCATOR: usize = 256;
const MAX_AGE_KEY: usize = 256;
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Invitation {
    pub id: [u8; 16],
    pub expires_at: u64,
    pub attempts_remaining: u8,
    binding_key: [u8; 32],
    request_key: [u8; 32],
}

impl Drop for Invitation {
    fn drop(&mut self) {
        self.binding_key.zeroize();
        self.request_key.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicInvitation {
    pub id: [u8; 16],
    pub expires_at: u64,
    pub binding_mac: [u8; 32],
}

impl PublicInvitation {
    pub fn short_id(&self) -> String {
        hex::encode_upper(&self.id[..4])
    }

    pub fn is_expired(&self) -> bool {
        now_unix() > self.expires_at
    }
}

#[derive(Clone, Debug)]
pub struct PendingRequest {
    pub id: [u8; 16],
    pub invitation_id: [u8; 16],
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RequestClaim {
    pub request_id: [u8; 16],
    pub invitation_id: [u8; 16],
    pub recipient: AuthorizedRecipient,
    nonce: [u8; 16],
    mac: [u8; 32],
}

#[derive(Debug)]
pub struct Vault {
    secrets: BTreeMap<String, String>,
    recipients: Vec<AuthorizedRecipient>,
    invitations: Vec<Invitation>,
    inbox_identity: String,
}

impl Vault {
    pub fn new(primary: AuthorizedRecipient) -> Self {
        Self {
            secrets: BTreeMap::new(),
            recipients: vec![primary],
            invitations: Vec::new(),
            inbox_identity: generate_inbox_identity(),
        }
    }

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

    pub fn recipients(&self) -> &[AuthorizedRecipient] {
        &self.recipients
    }

    pub fn invitations(&self) -> &[Invitation] {
        &self.invitations
    }

    pub fn rename_recipient(&mut self, index: usize, name: String) -> Result<()> {
        ensure!(!name.trim().is_empty(), "recipient name cannot be empty");
        ensure!(
            name.len() <= MAX_FRIENDLY_NAME,
            "recipient name is too long"
        );
        self.recipients
            .get_mut(index)
            .context("recipient no longer exists")?
            .name = name;
        Ok(())
    }

    pub fn remove_recipient(&mut self, age_recipient: &str) -> Result<AuthorizedRecipient> {
        ensure!(
            self.recipients.len() > 1,
            "cannot remove the vault's final recipient"
        );
        let index = self
            .recipients
            .iter()
            .position(|recipient| recipient.age_recipient == age_recipient)
            .context("recipient no longer exists")?;
        Ok(self.recipients.remove(index))
    }

    pub fn rotate_inbox_and_clear_invitations(&mut self) -> Vec<[u8; 16]> {
        let closed = self
            .invitations
            .iter()
            .map(|invitation| invitation.id)
            .collect::<Vec<_>>();
        self.invitations.clear();
        self.inbox_identity.zeroize();
        self.inbox_identity = generate_inbox_identity();
        closed
    }

    pub fn prune_expired_invitations(&mut self, now: u64) -> Vec<[u8; 16]> {
        let expired = self
            .invitations
            .iter()
            .filter(|invitation| invitation.expires_at < now)
            .map(|invitation| invitation.id)
            .collect::<Vec<_>>();
        self.invitations
            .retain(|invitation| invitation.expires_at >= now);
        expired
    }

    pub fn create_invitation(
        &mut self,
        vault_id: &[u8; 16],
        duration_minutes: u64,
        word_count: usize,
    ) -> Result<(PublicInvitation, String)> {
        ensure!(
            self.invitations.len() < MAX_INVITATIONS,
            "the vault already has the maximum number of invitations"
        );
        ensure!(
            (4..=6).contains(&word_count),
            "invitation phrases use 4 to 6 words"
        );
        ensure!(
            duration_minutes > 0 && duration_minutes <= 7 * 24 * 60,
            "invitation duration must be between 1 minute and 7 days"
        );

        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let words = bip39::Language::English.word_list();
        let phrase = (0..word_count)
            .map(|_| words[(OsRng.next_u32() & 2047) as usize])
            .collect::<Vec<_>>()
            .join(" ");
        let keys = derive_invitation_keys(vault_id, &id, &phrase)?;
        let expires_at = now_unix()
            .checked_add(duration_minutes.saturating_mul(60))
            .context("invitation expiry overflow")?;
        let public = PublicInvitation {
            id,
            expires_at,
            // Container::reseal replaces this placeholder with a binding over the
            // complete encrypted core before it is written.
            binding_mac: invitation_binding_mac(
                vault_id,
                &id,
                expires_at,
                &[0; 32],
                &keys.binding,
            )?,
        };
        self.invitations.push(Invitation {
            id,
            expires_at,
            attempts_remaining: 3,
            binding_key: keys.binding,
            request_key: keys.request,
        });
        Ok((public, phrase))
    }

    pub fn close_invitation(&mut self, id: &[u8; 16]) -> bool {
        let old_len = self.invitations.len();
        self.invitations.retain(|invitation| &invitation.id != id);
        self.invitations.len() != old_len
    }

    pub fn approve_request(&mut self, vault_id: &[u8; 16], claim: &RequestClaim) -> Result<()> {
        let invitation = self
            .invitations
            .iter_mut()
            .find(|invitation| invitation.id == claim.invitation_id)
            .context("the invitation is closed or unknown")?;
        ensure!(
            now_unix() <= invitation.expires_at,
            "the invitation has expired"
        );
        ensure!(
            invitation.attempts_remaining > 0,
            "the invitation is locked"
        );
        invitation.attempts_remaining -= 1;

        let encoded = claim.encode_without_mac(vault_id)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&invitation.request_key)
            .map_err(|_| anyhow::anyhow!("invalid invitation key"))?;
        mac.update(&encoded);
        ensure!(
            mac.verify_slice(&claim.mac).is_ok(),
            "the invitation phrase is incorrect"
        );
        ensure!(
            !self
                .recipients
                .iter()
                .any(|recipient| recipient.age_recipient == claim.recipient.age_recipient),
            "this recipient already has access"
        );
        ensure!(
            self.recipients.len() < MAX_RECIPIENTS,
            "too many recipients"
        );
        self.recipients.push(claim.recipient.clone());
        self.close_invitation(&claim.invitation_id);
        Ok(())
    }

    fn inbox_recipient(&self) -> Result<String> {
        let identity = age::x25519::Identity::from_str(&self.inbox_identity)
            .map_err(|error| anyhow::anyhow!("invalid request inbox identity: {error}"))?;
        Ok(identity.to_public().to_string())
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(self.secrets.len() <= MAX_SECRETS, "too many secrets");
        ensure!(
            self.recipients.len() <= MAX_RECIPIENTS,
            "too many recipients"
        );
        ensure!(
            self.invitations.len() <= MAX_INVITATIONS,
            "too many invitations"
        );
        ensure!(
            self.inbox_identity.len() <= MAX_AGE_KEY,
            "inbox identity is too long"
        );

        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(PAYLOAD_MAGIC);
        put_string_u16(&mut bytes, &self.inbox_identity)?;
        bytes.extend_from_slice(&(self.recipients.len() as u16).to_be_bytes());
        for recipient in &self.recipients {
            ensure!(
                !recipient.name.trim().is_empty(),
                "recipient name cannot be empty"
            );
            ensure!(
                recipient.name.len() <= MAX_FRIENDLY_NAME,
                "recipient name is too long"
            );
            ensure!(
                recipient.backend.len() <= MAX_BACKEND_ID,
                "backend ID is too long"
            );
            ensure!(
                recipient.locator.len() <= MAX_LOCATOR,
                "identity locator is too long"
            );
            ensure!(
                recipient.age_recipient.len() <= MAX_AGE_KEY,
                "age recipient is too long"
            );
            put_string_u16(&mut bytes, &recipient.name)?;
            put_string_u16(&mut bytes, &recipient.backend)?;
            put_string_u16(&mut bytes, &recipient.locator)?;
            put_string_u16(&mut bytes, &recipient.age_recipient)?;
        }
        bytes.extend_from_slice(&(self.invitations.len() as u16).to_be_bytes());
        for invitation in &self.invitations {
            bytes.extend_from_slice(&invitation.id);
            bytes.extend_from_slice(&invitation.expires_at.to_be_bytes());
            bytes.push(invitation.attempts_remaining);
            bytes.extend_from_slice(&invitation.binding_key);
            bytes.extend_from_slice(&invitation.request_key);
        }
        bytes.extend_from_slice(&(self.secrets.len() as u32).to_be_bytes());
        for (name, value) in &self.secrets {
            ensure!(!name.is_empty(), "secret names cannot be empty");
            ensure!(name.len() <= MAX_NAME_LEN, "secret name is too long");
            ensure!(value.len() <= MAX_VALUE_LEN, "secret value is too long");
            put_string_u32(&mut bytes, name)?;
            put_string_u32(&mut bytes, value)?;
        }
        Ok(bytes)
    }

    fn decode(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let mut cursor = Cursor::new(&bytes);
        ensure!(cursor.take(8)? == PAYLOAD_MAGIC, "invalid nit payload");
        let inbox_identity = cursor.string_u16(MAX_AGE_KEY, "inbox identity")?;
        let recipient_count = cursor.u16()? as usize;
        ensure!(
            recipient_count > 0 && recipient_count <= MAX_RECIPIENTS,
            "invalid recipient count"
        );
        let mut vault = Self {
            secrets: BTreeMap::new(),
            recipients: Vec::with_capacity(recipient_count),
            invitations: Vec::new(),
            inbox_identity,
        };
        for _ in 0..recipient_count {
            let name = cursor.string_u16(MAX_FRIENDLY_NAME, "recipient name")?;
            ensure!(!name.trim().is_empty(), "recipient name cannot be empty");
            vault.recipients.push(AuthorizedRecipient {
                name,
                backend: cursor.string_u16(MAX_BACKEND_ID, "backend ID")?,
                locator: cursor.string_u16(MAX_LOCATOR, "identity locator")?,
                age_recipient: cursor.string_u16(MAX_AGE_KEY, "age recipient")?,
            });
        }
        let invitation_count = cursor.u16()? as usize;
        ensure!(
            invitation_count <= MAX_INVITATIONS,
            "invalid invitation count"
        );
        for _ in 0..invitation_count {
            vault.invitations.push(Invitation {
                id: cursor.array()?,
                expires_at: cursor.u64()?,
                attempts_remaining: cursor.u8()?,
                binding_key: cursor.array()?,
                request_key: cursor.array()?,
            });
        }
        let secret_count = cursor.u32()? as usize;
        ensure!(
            secret_count <= MAX_SECRETS,
            "vault contains too many secrets"
        );
        for _ in 0..secret_count {
            let name = cursor.string_u32(MAX_NAME_LEN, "secret name")?;
            ensure!(!name.is_empty(), "secret name cannot be empty");
            let value = cursor.string_u32(MAX_VALUE_LEN, "secret value")?;
            ensure!(
                vault.secrets.insert(name, value).is_none(),
                "duplicate secret name"
            );
        }
        ensure!(cursor.remaining() == 0, "trailing bytes in decrypted vault");
        Ok(vault)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        for value in self.secrets.values_mut() {
            value.zeroize();
        }
        self.inbox_identity.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct Container {
    pub vault_id: [u8; 16],
    pub generation: u64,
    pub inbox_recipient: String,
    pub routes: Vec<AuthorizedRecipient>,
    pub invitations: Vec<PublicInvitation>,
    pub requests: Vec<PendingRequest>,
    age_payload: Vec<u8>,
}

impl Container {
    pub fn new(vault: &Vault) -> Result<Self> {
        let mut vault_id = [0u8; 16];
        OsRng.fill_bytes(&mut vault_id);
        let mut container = Self {
            vault_id,
            generation: 0,
            inbox_recipient: vault.inbox_recipient()?,
            routes: Vec::new(),
            invitations: Vec::new(),
            requests: Vec::new(),
            age_payload: Vec::new(),
        };
        container.reseal(vault)?;
        Ok(container)
    }

    pub fn reseal(&mut self, vault: &Vault) -> Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .context("vault generation overflow")?;
        self.routes = vault.recipients.clone();
        self.inbox_recipient = vault.inbox_recipient()?;
        self.age_payload = encrypt_vault(vault)?;
        let core_digest = self.core_digest();
        self.invitations = vault
            .invitations
            .iter()
            .map(|invitation| {
                Ok(PublicInvitation {
                    id: invitation.id,
                    expires_at: invitation.expires_at,
                    binding_mac: invitation_binding_mac(
                        &self.vault_id,
                        &invitation.id,
                        invitation.expires_at,
                        &core_digest,
                        &invitation.binding_key,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }

    fn core_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"nit/container/v3/core");
        digest.update(self.vault_id);
        digest.update(self.generation.to_be_bytes());
        digest.update((self.inbox_recipient.len() as u16).to_be_bytes());
        digest.update(self.inbox_recipient.as_bytes());
        digest.update((self.routes.len() as u16).to_be_bytes());
        for route in &self.routes {
            digest.update((route.backend.len() as u16).to_be_bytes());
            digest.update(route.backend.as_bytes());
            digest.update((route.locator.len() as u16).to_be_bytes());
            digest.update(route.locator.as_bytes());
            digest.update((route.age_recipient.len() as u16).to_be_bytes());
            digest.update(route.age_recipient.as_bytes());
        }
        digest.update((self.age_payload.len() as u64).to_be_bytes());
        digest.update(&self.age_payload);
        digest.finalize().into()
    }

    pub fn open(self, identity: &dyn UnlockIdentity) -> Result<(Vault, Self)> {
        let decryptor =
            Decryptor::new_buffered(self.age_payload.as_slice()).context("invalid age payload")?;
        let mut reader = match decryptor.decrypt(std::iter::once(identity.age_identity())) {
            Ok(reader) => reader,
            Err(error) => {
                if let Some(source) = identity.take_error() {
                    return Err(source);
                }
                return Err(error).context("cannot decrypt vault");
            }
        };
        let mut plaintext = Zeroizing::new(Vec::new());
        reader
            .by_ref()
            .take(MAX_FILE_SIZE + 1)
            .read_to_end(&mut plaintext)
            .context("cannot read decrypted vault")?;
        ensure!(
            plaintext.len() as u64 <= MAX_FILE_SIZE,
            "decrypted vault is too large"
        );
        let vault = Vault::decode(plaintext)?;
        ensure!(
            vault.inbox_recipient()? == self.inbox_recipient,
            "request inbox metadata mismatch"
        );
        ensure!(
            vault.recipients.len() == self.routes.len()
                && vault
                    .recipients
                    .iter()
                    .zip(&self.routes)
                    .all(|(recipient, route)| recipient.same_identity(route)),
            "recipient metadata mismatch"
        );
        let core_digest = self.core_digest();
        let expected_invitations = vault
            .invitations
            .iter()
            .map(|invitation| {
                Ok(PublicInvitation {
                    id: invitation.id,
                    expires_at: invitation.expires_at,
                    binding_mac: invitation_binding_mac(
                        &self.vault_id,
                        &invitation.id,
                        invitation.expires_at,
                        &core_digest,
                        &invitation.binding_key,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            expected_invitations == self.invitations,
            "public invitation metadata was tampered with"
        );
        Ok((vault, self))
    }

    pub fn verify_invitation(&self, invitation: &PublicInvitation, phrase: &str) -> Result<()> {
        self.verified_invitation(invitation, phrase).map(|_| ())
    }

    fn verified_invitation(
        &self,
        invitation: &PublicInvitation,
        phrase: &str,
    ) -> Result<(PublicInvitation, InvitationKeys)> {
        let invitation = self
            .invitations
            .iter()
            .find(|item| item.id == invitation.id)
            .cloned()
            .context("unknown invitation")?;
        ensure!(!invitation.is_expired(), "the invitation has expired");
        let keys = derive_invitation_keys(&self.vault_id, &invitation.id, phrase)?;
        let expected_binding = invitation_binding_mac(
            &self.vault_id,
            &invitation.id,
            invitation.expires_at,
            &self.core_digest(),
            &keys.binding,
        )?;
        ensure!(
            bool::from(expected_binding.ct_eq(&invitation.binding_mac)),
            "invitation phrase is incorrect or the repository copy was tampered with"
        );
        Ok((invitation, keys))
    }

    pub fn create_request(
        &mut self,
        invitation: &PublicInvitation,
        phrase: &str,
        recipient: AuthorizedRecipient,
    ) -> Result<()> {
        ensure!(
            self.requests.len() < MAX_REQUESTS,
            "too many pending requests"
        );
        let (invitation, keys) = self.verified_invitation(invitation, phrase)?;
        let mut request_id = [0u8; 16];
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut request_id);
        OsRng.fill_bytes(&mut nonce);
        let mut claim = RequestClaim {
            request_id,
            invitation_id: invitation.id,
            recipient,
            nonce,
            mac: [0; 32],
        };
        let encoded = claim.encode_without_mac(&self.vault_id)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&keys.request)
            .map_err(|_| anyhow::anyhow!("invalid invitation key"))?;
        mac.update(&encoded);
        claim.mac.copy_from_slice(&mac.finalize().into_bytes());
        let plaintext = Zeroizing::new(claim.encode(&self.vault_id)?);
        let inbox = age::x25519::Recipient::from_str(&self.inbox_recipient)
            .map_err(|error| anyhow::anyhow!("invalid request inbox recipient: {error}"))?;
        let encryptor = Encryptor::with_recipients(std::iter::once(&inbox as &dyn age::Recipient))
            .context("cannot initialize request encryption")?;
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext)?;
        writer.write_all(&plaintext)?;
        writer.finish()?;
        ensure!(
            ciphertext.len() <= MAX_REQUEST_SIZE,
            "encrypted request is too large"
        );
        self.requests.push(PendingRequest {
            id: request_id,
            invitation_id: invitation.id,
            ciphertext,
        });
        Ok(())
    }

    pub fn decrypt_requests(&self, vault: &Vault) -> Vec<Result<RequestClaim>> {
        self.requests
            .iter()
            .map(|request| decrypt_request(request, &vault.inbox_identity, &self.vault_id))
            .collect()
    }

    pub fn remove_request(&mut self, id: &[u8; 16]) -> bool {
        let old_len = self.requests.len();
        self.requests.retain(|request| &request.id != id);
        self.requests.len() != old_len
    }

    pub fn remove_requests_for_invitation(&mut self, invitation_id: &[u8; 16]) -> usize {
        let old_len = self.requests.len();
        self.requests
            .retain(|request| &request.invitation_id != invitation_id);
        old_len - self.requests.len()
    }

    pub fn clear_requests(&mut self) -> usize {
        let count = self.requests.len();
        self.requests.clear();
        count
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.routes.len() <= MAX_RECIPIENTS,
            "too many recipient routes"
        );
        ensure!(
            self.invitations.len() <= MAX_INVITATIONS,
            "too many public invitations"
        );
        ensure!(self.requests.len() <= MAX_REQUESTS, "too many requests");
        ensure!(
            self.inbox_recipient.len() <= MAX_AGE_KEY,
            "inbox recipient is too long"
        );
        ensure!(
            self.age_payload.len() as u64 <= MAX_FILE_SIZE,
            "age payload is too large"
        );

        let mut output = Vec::new();
        output.extend_from_slice(CONTAINER_MAGIC);
        output.extend_from_slice(&self.vault_id);
        output.extend_from_slice(&self.generation.to_be_bytes());
        put_string_u16(&mut output, &self.inbox_recipient)?;
        output.extend_from_slice(&(self.routes.len() as u16).to_be_bytes());
        for route in &self.routes {
            put_string_u16(&mut output, &route.backend)?;
            put_string_u16(&mut output, &route.locator)?;
            put_string_u16(&mut output, &route.age_recipient)?;
        }
        output.extend_from_slice(&(self.invitations.len() as u16).to_be_bytes());
        for invitation in &self.invitations {
            output.extend_from_slice(&invitation.id);
            output.extend_from_slice(&invitation.expires_at.to_be_bytes());
            output.extend_from_slice(&invitation.binding_mac);
        }
        output.extend_from_slice(&(self.age_payload.len() as u64).to_be_bytes());
        output.extend_from_slice(&self.age_payload);
        output.extend_from_slice(&(self.requests.len() as u16).to_be_bytes());
        for request in &self.requests {
            ensure!(
                request.ciphertext.len() <= MAX_REQUEST_SIZE,
                "request is too large"
            );
            output.extend_from_slice(&request.id);
            output.extend_from_slice(&request.invitation_id);
            output.extend_from_slice(&(request.ciphertext.len() as u32).to_be_bytes());
            output.extend_from_slice(&request.ciphertext);
        }
        ensure!(
            output.len() as u64 <= MAX_FILE_SIZE,
            "encoded vault is too large"
        );
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_FILE_SIZE,
            "vault is larger than 64 MiB"
        );
        let mut cursor = Cursor::new(bytes);
        ensure!(cursor.take(8)? == CONTAINER_MAGIC, "not a nit V3 vault");
        let vault_id = cursor.array()?;
        let generation = cursor.u64()?;
        let inbox_recipient = cursor.string_u16(MAX_AGE_KEY, "inbox recipient")?;
        age::x25519::Recipient::from_str(&inbox_recipient)
            .map_err(|error| anyhow::anyhow!("invalid inbox recipient: {error}"))?;
        let route_count = cursor.u16()? as usize;
        ensure!(
            route_count > 0 && route_count <= MAX_RECIPIENTS,
            "invalid route count"
        );
        let mut routes = Vec::with_capacity(route_count);
        for index in 0..route_count {
            routes.push(AuthorizedRecipient {
                name: format!("Recipient {}", index + 1),
                backend: cursor.string_u16(MAX_BACKEND_ID, "backend ID")?,
                locator: cursor.string_u16(MAX_LOCATOR, "identity locator")?,
                age_recipient: cursor.string_u16(MAX_AGE_KEY, "age recipient")?,
            });
        }
        let invitation_count = cursor.u16()? as usize;
        ensure!(
            invitation_count <= MAX_INVITATIONS,
            "invalid invitation count"
        );
        let mut invitations = Vec::with_capacity(invitation_count);
        for _ in 0..invitation_count {
            invitations.push(PublicInvitation {
                id: cursor.array()?,
                expires_at: cursor.u64()?,
                binding_mac: cursor.array()?,
            });
        }
        let age_len = usize::try_from(cursor.u64()?).context("age payload length overflow")?;
        ensure!(
            age_len <= MAX_FILE_SIZE as usize,
            "age payload is too large"
        );
        let age_payload = cursor.take(age_len)?.to_vec();
        let request_count = cursor.u16()? as usize;
        ensure!(request_count <= MAX_REQUESTS, "invalid request count");
        let mut requests = Vec::with_capacity(request_count);
        for _ in 0..request_count {
            let id = cursor.array()?;
            let invitation_id = cursor.array()?;
            let length = cursor.u32()? as usize;
            ensure!(length <= MAX_REQUEST_SIZE, "request is too large");
            let ciphertext = cursor.take(length)?.to_vec();
            requests.push(PendingRequest {
                id,
                invitation_id,
                ciphertext,
            });
        }
        ensure!(cursor.remaining() == 0, "trailing bytes in nit container");
        Ok(Self {
            vault_id,
            generation,
            inbox_recipient,
            routes,
            invitations,
            requests,
            age_payload,
        })
    }
}

fn encrypt_vault(vault: &Vault) -> Result<Vec<u8>> {
    let recipients = vault
        .recipients
        .iter()
        .map(|recipient| {
            recipient
                .age_recipient
                .parse::<age::x25519::Recipient>()
                .map_err(|error| anyhow::anyhow!("invalid age recipient: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let encryptor = Encryptor::with_recipients(
        recipients
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient),
    )
    .context("cannot initialize vault encryption")?;
    let plaintext = vault.encode()?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(&plaintext)?;
    writer.finish()?;
    Ok(ciphertext)
}

fn decrypt_request(
    request: &PendingRequest,
    inbox_identity: &str,
    vault_id: &[u8; 16],
) -> Result<RequestClaim> {
    let identity = age::x25519::Identity::from_str(inbox_identity)
        .map_err(|error| anyhow::anyhow!("invalid request inbox identity: {error}"))?;
    let decryptor = Decryptor::new_buffered(request.ciphertext.as_slice())
        .context("invalid encrypted request")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("cannot decrypt access request")?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take((MAX_REQUEST_SIZE + 1) as u64)
        .read_to_end(&mut plaintext)?;
    ensure!(
        plaintext.len() <= MAX_REQUEST_SIZE,
        "request plaintext is too large"
    );
    let claim = RequestClaim::decode(&plaintext, vault_id)?;
    ensure!(claim.request_id == request.id, "request ID mismatch");
    ensure!(
        claim.invitation_id == request.invitation_id,
        "invitation ID mismatch"
    );
    Ok(claim)
}

impl RequestClaim {
    fn encode_without_mac(&self, vault_id: &[u8; 16]) -> Result<Vec<u8>> {
        ensure!(
            !self.recipient.name.trim().is_empty(),
            "requested name cannot be empty"
        );
        ensure!(
            self.recipient.name.len() <= MAX_FRIENDLY_NAME,
            "requested name is too long"
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(vault_id);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.invitation_id);
        put_string_u16(&mut bytes, &self.recipient.name)?;
        put_string_u16(&mut bytes, &self.recipient.backend)?;
        put_string_u16(&mut bytes, &self.recipient.locator)?;
        put_string_u16(&mut bytes, &self.recipient.age_recipient)?;
        bytes.extend_from_slice(&self.nonce);
        Ok(bytes)
    }

    fn encode(&self, vault_id: &[u8; 16]) -> Result<Vec<u8>> {
        let mut bytes = self.encode_without_mac(vault_id)?;
        bytes.extend_from_slice(&self.mac);
        Ok(bytes)
    }

    fn decode(bytes: &[u8], expected_vault_id: &[u8; 16]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        ensure!(cursor.take(8)? == REQUEST_MAGIC, "invalid request payload");
        ensure!(
            cursor.take(16)? == expected_vault_id,
            "request targets another vault"
        );
        let request_id = cursor.array()?;
        let invitation_id = cursor.array()?;
        let name = cursor.string_u16(MAX_FRIENDLY_NAME, "requested recipient name")?;
        ensure!(!name.trim().is_empty(), "requested name cannot be empty");
        let recipient = AuthorizedRecipient {
            name,
            backend: cursor.string_u16(MAX_BACKEND_ID, "requested backend ID")?,
            locator: cursor.string_u16(MAX_LOCATOR, "requested identity locator")?,
            age_recipient: cursor.string_u16(MAX_AGE_KEY, "requested age recipient")?,
        };
        let nonce = cursor.array()?;
        let mac = cursor.array()?;
        ensure!(cursor.remaining() == 0, "trailing bytes in request");
        Ok(Self {
            request_id,
            invitation_id,
            recipient,
            nonce,
            mac,
        })
    }
}

fn generate_inbox_identity() -> String {
    let identity = age::x25519::Identity::generate();
    age::secrecy::ExposeSecret::expose_secret(&identity.to_string()).to_owned()
}

#[derive(Debug, Eq, PartialEq)]
struct InvitationKeys {
    binding: [u8; 32],
    request: [u8; 32],
}

impl Drop for InvitationKeys {
    fn drop(&mut self) {
        self.binding.zeroize();
        self.request.zeroize();
    }
}

fn derive_invitation_keys(
    vault_id: &[u8; 16],
    invitation_id: &[u8; 16],
    phrase: &str,
) -> Result<InvitationKeys> {
    let canonical = Zeroizing::new(canonical_phrase(phrase)?);
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"nit/invite/v2/argon2id");
    salt_hasher.update(vault_id);
    salt_hasher.update(invitation_id);
    let salt = salt_hasher.finalize();
    #[cfg(test)]
    let memory_kib = 1024;
    #[cfg(not(test))]
    let memory_kib = 64 * 1024;
    let params = Params::new(memory_kib, 3, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(canonical.as_bytes(), &salt, master.as_mut())
        .map_err(|error| anyhow::anyhow!("invitation key derivation failed: {error}"))?;
    Ok(InvitationKeys {
        binding: derive_invitation_subkey(&master, INVITE_BINDING_LABEL)?,
        request: derive_invitation_subkey(&master, INVITE_REQUEST_LABEL)?,
    })
}

fn derive_invitation_subkey(master: &[u8; 32], label: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(master)
        .map_err(|_| anyhow::anyhow!("invalid invitation master key"))?;
    mac.update(label);
    Ok(mac.finalize().into_bytes().into())
}

fn invitation_binding_mac(
    vault_id: &[u8; 16],
    invitation_id: &[u8; 16],
    expires_at: u64,
    core_digest: &[u8; 32],
    binding_key: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(binding_key)
        .map_err(|_| anyhow::anyhow!("invalid invitation binding key"))?;
    mac.update(INVITE_BINDING_LABEL);
    mac.update(vault_id);
    mac.update(invitation_id);
    mac.update(&expires_at.to_be_bytes());
    mac.update(core_digest);
    Ok(mac.finalize().into_bytes().into())
}

pub fn validate_invitation_phrase(phrase: &str) -> Result<()> {
    canonical_phrase(phrase).map(|_| ())
}

fn canonical_phrase(phrase: &str) -> Result<String> {
    let parts = phrase
        .split(|character: char| character.is_whitespace() || character == '-')
        .filter(|part| !part.is_empty())
        .map(|part| Zeroizing::new(part.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    ensure!(
        (4..=6).contains(&parts.len()),
        "invitation phrase must contain 4 to 6 words"
    );
    let words = bip39::Language::English.word_list();
    ensure!(
        parts
            .iter()
            .all(|part| words.binary_search(&part.as_str()).is_ok()),
        "invitation phrase contains an unknown word; type all words on one line separated by spaces"
    );
    Ok(parts
        .iter()
        .map(|part| part.as_str())
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn put_string_u16(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).context("string is too long")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_string_u32(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len()).context("string is too long")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
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
            .context("length overflow")?;
        if end > self.bytes.len() {
            bail!("truncated data");
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

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn string_u16(&mut self, max: usize, what: &str) -> Result<String> {
        let length = self.u16()? as usize;
        ensure!(length <= max, "{what} is too long");
        zeroizing_string_from_utf8(self.take(length)?.to_vec(), what)
    }

    fn string_u32(&mut self, max: usize, what: &str) -> Result<String> {
        let length = self.u32()? as usize;
        ensure!(length <= max, "{what} is too long");
        zeroizing_string_from_utf8(self.take(length)?.to_vec(), what)
    }
}

fn zeroizing_string_from_utf8(bytes: Vec<u8>, what: &str) -> Result<String> {
    match String::from_utf8(bytes) {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            bail!("{what} is not UTF-8")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(name: &str) -> AuthorizedRecipient {
        let identity = age::x25519::Identity::generate();
        AuthorizedRecipient {
            name: name.into(),
            backend: "test".into(),
            locator: name.into(),
            age_recipient: identity.to_public().to_string(),
        }
    }

    #[test]
    fn phrase_is_canonical_and_domain_bound() {
        let vault = [1u8; 16];
        let invitation = [2u8; 16];
        assert_eq!(
            derive_invitation_keys(&vault, &invitation, "abandon-ability able about").unwrap(),
            derive_invitation_keys(&vault, &invitation, "ABANDON ability   able about").unwrap()
        );
        assert_ne!(
            derive_invitation_keys(&vault, &invitation, "abandon ability able about").unwrap(),
            derive_invitation_keys(&[3u8; 16], &invitation, "abandon ability able about").unwrap()
        );
    }

    #[test]
    fn payload_round_trip_preserves_metadata() {
        let mut vault = Vault::new(recipient("Alice – Work YubiKey"));
        vault.insert("TOKEN".into(), "secret".into());
        vault.create_invitation(&[7u8; 16], 30, 4).unwrap();
        let encoded = vault.encode().unwrap();
        let decoded = Vault::decode(encoded).unwrap();
        assert_eq!(decoded.get("TOKEN"), Some("secret"));
        assert_eq!(decoded.recipients()[0].name, "Alice – Work YubiKey");
        assert_eq!(decoded.invitations().len(), 1);
    }

    #[test]
    fn expired_invitations_are_pruned() {
        let mut vault = Vault::new(recipient("Owner"));
        vault.invitations.push(Invitation {
            id: [1; 16],
            expires_at: 99,
            attempts_remaining: 3,
            binding_key: [5; 32],
            request_key: [2; 32],
        });
        vault.invitations.push(Invitation {
            id: [3; 16],
            expires_at: 101,
            attempts_remaining: 3,
            binding_key: [6; 32],
            request_key: [4; 32],
        });
        assert_eq!(vault.prune_expired_invitations(100), vec![[1; 16]]);
        assert_eq!(vault.invitations().len(), 1);
        assert_eq!(vault.invitations()[0].id, [3; 16]);
    }

    #[test]
    fn final_recipient_cannot_be_removed() {
        let mut vault = Vault::new(recipient("Owner"));
        let owner_key = vault.recipients()[0].age_recipient.clone();
        assert!(vault.remove_recipient(&owner_key).is_err());

        let backup = recipient("Backup");
        let backup_key = backup.age_recipient.clone();
        vault.recipients.push(backup);
        vault.create_invitation(&[8; 16], 30, 4).unwrap();
        let old_inbox = vault.inbox_recipient().unwrap();
        let removed = vault.remove_recipient(&backup_key).unwrap();
        let closed = vault.rotate_inbox_and_clear_invitations();
        assert_eq!(removed.name, "Backup");
        assert_eq!(vault.recipients().len(), 1);
        assert_eq!(closed.len(), 1);
        assert!(vault.invitations().is_empty());
        assert_ne!(vault.inbox_recipient().unwrap(), old_inbox);
    }

    #[test]
    fn container_rejects_trailing_data() {
        let vault = Vault::new(recipient("Primary"));
        let container = Container::new(&vault).unwrap();
        let mut encoded = container.encode().unwrap();
        encoded.push(0);
        assert!(Container::decode(&encoded).is_err());
    }

    #[test]
    fn invitation_request_can_be_approved() {
        let mut vault = Vault::new(recipient("Owner"));
        let mut container = Container::new(&vault).unwrap();
        let (invitation, phrase) = vault.create_invitation(&container.vault_id, 30, 4).unwrap();
        container.reseal(&vault).unwrap();
        let encrypted_vault_before_request = container.age_payload.clone();
        container
            .create_request(&invitation, &phrase, recipient("Alice"))
            .unwrap();
        assert_eq!(container.age_payload, encrypted_vault_before_request);

        let claim = container
            .decrypt_requests(&vault)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        let request_id = claim.request_id;
        vault.approve_request(&container.vault_id, &claim).unwrap();
        container.remove_request(&request_id);
        container.reseal(&vault).unwrap();

        assert_eq!(vault.recipients().len(), 2);
        assert_eq!(vault.recipients()[1].name, "Alice");
        assert!(vault.invitations().is_empty());
        assert!(container.invitations.is_empty());
        assert!(container.requests.is_empty());
        assert_eq!(container.routes.len(), 2);
    }

    #[test]
    fn wrong_phrase_or_tampered_inbox_is_rejected_before_request_creation() {
        let mut vault = Vault::new(recipient("Owner"));
        let mut container = Container::new(&vault).unwrap();
        let (invitation, phrase) = vault.create_invitation(&container.vault_id, 30, 4).unwrap();
        container.reseal(&vault).unwrap();

        assert!(container
            .create_request(
                &invitation,
                "abandon ability able about",
                recipient("Mallory")
            )
            .is_err());
        assert!(container.requests.is_empty());

        let mut payload_tampered = container.clone();
        let last = payload_tampered.age_payload.len() - 1;
        payload_tampered.age_payload[last] ^= 1;
        assert!(payload_tampered
            .create_request(&invitation, &phrase, recipient("Mallory"))
            .is_err());

        let attacker = age::x25519::Identity::generate();
        container.inbox_recipient = attacker.to_public().to_string();
        assert!(container
            .create_request(&invitation, &phrase, recipient("Mallory"))
            .is_err());
        assert!(container.requests.is_empty());
    }

    #[test]
    fn age_payload_opens_for_each_recipient() {
        fn pair(name: &str, locator: &str) -> (age::x25519::Identity, AuthorizedRecipient) {
            let identity = age::x25519::Identity::generate();
            let recipient = AuthorizedRecipient {
                name: name.into(),
                backend: "test".into(),
                locator: locator.into(),
                age_recipient: identity.to_public().to_string(),
            };
            (identity, recipient)
        }

        let (alice_identity, alice) = pair("Alice", "1");
        let (bob_identity, bob) = pair("Bob", "2");
        let mut vault = Vault::new(alice);
        vault.recipients.push(bob);
        vault.insert("TOKEN".into(), "shared secret".into());
        let encrypted = encrypt_vault(&vault).unwrap();

        for identity in [&alice_identity, &bob_identity] {
            let decryptor = Decryptor::new_buffered(encrypted.as_slice()).unwrap();
            let mut reader = decryptor
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .unwrap();
            let mut plaintext = Zeroizing::new(Vec::new());
            reader.read_to_end(&mut plaintext).unwrap();
            let opened = Vault::decode(plaintext).unwrap();
            assert_eq!(opened.get("TOKEN"), Some("shared secret"));
        }
    }
}
