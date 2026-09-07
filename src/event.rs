use std::collections::BTreeSet;

use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::identity::IdentitySession;

pub type Hash = [u8; 32];
pub type VaultId = [u8; 32];
pub const LOG_MAGIC: &[u8; 8] = b"GVLOG006";
pub const EVENT_MAGIC: &[u8; 8] = b"GVEVT006";
pub const FORMAT_VERSION: u16 = 6;
pub const MAX_EVENT_SIZE: usize = 20 * 1024 * 1024;
pub const MAX_LOG_SIZE: usize = 64 * 1024 * 1024;
pub const MAX_MEMBERS: usize = 64;
pub const MAX_KEY_LEN: usize = 1_024;
pub const MAX_VALUE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_MUTATION_PARENTS: usize = 1_024;

const SIGNATURE_DOMAIN: &[u8] = b"git-vault/event-signature/v1";
const EVENT_HASH_DOMAIN: &[u8] = b"git-vault/event-hash/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Member,
    Owner,
}

impl Role {
    fn encode(self) -> u8 {
        match self {
            Self::Member => 1,
            Self::Owner => 2,
        }
    }

    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Member),
            2 => Ok(Self::Owner),
            _ => bail!("unknown member role {value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberIdentity {
    pub name: String,
    pub signing_public_key: [u8; 32],
    pub encryption_public_key: [u8; 32],
}

impl MemberIdentity {
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"git-vault/identity-fingerprint/v1");
        hasher.update(self.signing_public_key);
        hasher.update(self.encryption_public_key);
        hex::encode_upper(&hasher.finalize()[..8])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedEpochKey {
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochMember {
    pub identity: MemberIdentity,
    pub role: Role,
    pub wrapped_epoch_key: WrappedEpochKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedSnapshot {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipEpoch {
    pub epoch_number: u64,
    pub members: Vec<EpochMember>,
    pub snapshot: EncryptedSnapshot,
    /// Mutation DAG heads from the preceding epoch that the owner included in this snapshot.
    /// Empty for Genesis.
    pub previous_epoch_heads: Vec<Hash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    Text,
    Number,
    Boolean,
    Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventPayload {
    Genesis(MembershipEpoch),
    MembershipEpoch(MembershipEpoch),
    Mutation {
        epoch_number: u64,
        /// Current mutation DAG heads observed by the writer. Mutations advance this DAG,
        /// not the linear membership control chain.
        parents: Vec<Hash>,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
}

impl EventPayload {
    pub fn type_code(&self) -> u16 {
        match self {
            Self::Genesis(_) => 1,
            Self::MembershipEpoch(_) => 2,
            Self::Mutation { .. } => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub vault_id: VaultId,
    pub parent_trust_hash: Hash,
    pub author_signing_key: [u8; 32],
    pub payload: EventPayload,
    pub signature: [u8; 64],
}

impl Event {
    pub fn unsigned(
        vault_id: VaultId,
        parent_trust_hash: Hash,
        author_signing_key: [u8; 32],
        payload: EventPayload,
    ) -> Self {
        Self {
            vault_id,
            parent_trust_hash,
            author_signing_key,
            payload,
            signature: [0; 64],
        }
    }

    pub fn sign(mut self, identity: &mut dyn IdentitySession) -> Result<Self> {
        ensure!(
            identity.identity().signing_public_key == self.author_signing_key,
            "signing session does not match event author"
        );
        self.signature = identity.sign(&self.signing_digest()?)?;
        self.verify_structure()?;
        Ok(self)
    }

    pub fn signing_digest(&self) -> Result<Hash> {
        let unsigned = self.encode_without_signature()?;
        let mut hasher = Sha256::new();
        hasher.update(SIGNATURE_DOMAIN);
        hasher.update(unsigned);
        Ok(hasher.finalize().into())
    }

    pub fn event_hash(&self) -> Result<Hash> {
        self.verify_structure()?;
        self.verified_event_hash()
    }

    pub(crate) fn verified_event_hash(&self) -> Result<Hash> {
        let mut hasher = Sha256::new();
        hasher.update(EVENT_HASH_DOMAIN);
        hasher.update(self.encode_without_signature()?);
        hasher.update(self.signature);
        Ok(hasher.finalize().into())
    }

    pub fn verify_structure(&self) -> Result<()> {
        ensure!(self.vault_id != [0; 32], "vault ID cannot be zero");
        validate_payload(&self.payload)?;
        let key = VerifyingKey::from_bytes(&self.author_signing_key)
            .context("invalid Ed25519 author key")?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signing_digest()?, &signature)
            .context("invalid event signature")?;
        ensure!(
            self.encode()?.len() <= MAX_EVENT_SIZE,
            "event exceeds the size limit"
        );
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = self.encode_without_signature()?;
        output.extend_from_slice(&self.signature);
        ensure!(
            output.len() <= MAX_EVENT_SIZE,
            "event exceeds the size limit"
        );
        Ok(output)
    }

    fn encode_without_signature(&self) -> Result<Vec<u8>> {
        let payload = encode_payload(&self.payload)?;
        let mut output = Vec::with_capacity(112 + payload.len());
        output.extend_from_slice(EVENT_MAGIC);
        put_u16(&mut output, FORMAT_VERSION);
        output.extend_from_slice(&self.vault_id);
        put_u16(&mut output, self.payload.type_code());
        output.extend_from_slice(&self.parent_trust_hash);
        output.extend_from_slice(&self.author_signing_key);
        put_u32(&mut output, payload.len())?;
        output.extend_from_slice(&payload);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EVENT_SIZE,
            "event exceeds the size limit"
        );
        let mut decoder = Decoder::new(bytes);
        ensure!(decoder.take(8)? == EVENT_MAGIC, "invalid event magic");
        ensure!(
            decoder.u16()? == FORMAT_VERSION,
            "unsupported event format version"
        );
        let vault_id = decoder.array()?;
        let type_code = decoder.u16()?;
        let parent_trust_hash = decoder.array()?;
        let author_signing_key = decoder.array()?;
        let payload_len = decoder.u32()? as usize;
        ensure!(payload_len <= MAX_EVENT_SIZE, "event payload is too large");
        let payload_bytes = decoder.take(payload_len)?;
        let signature = decoder.array()?;
        decoder.finish()?;
        let payload = decode_payload(type_code, payload_bytes)?;
        let event = Self {
            vault_id,
            parent_trust_hash,
            author_signing_key,
            payload,
            signature,
        };
        event.verify_structure()?;
        Ok(event)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventLog {
    pub events: Vec<Event>,
    pub diagnostics: Vec<String>,
}

impl EventLog {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut indexed = self
            .events
            .iter()
            .map(|event| {
                event.verify_structure()?;
                Ok((event.verified_event_hash()?, event))
            })
            .collect::<Result<Vec<_>>>()?;
        let root = indexed
            .iter()
            .position(|(_, event)| matches!(event.payload, EventPayload::Genesis(_)));
        let root = root.map(|index| indexed.remove(index));
        indexed.sort_by_key(|(hash, _)| *hash);

        let mut output = Vec::new();
        output.extend_from_slice(LOG_MAGIC);
        if let Some((_, event)) = root {
            put_event_record(&mut output, event)?;
        }
        for (_, event) in indexed {
            put_event_record(&mut output, event)?;
        }
        ensure!(
            output.len() <= MAX_LOG_SIZE,
            "vault event collection exceeds the size limit"
        );
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_LOG_SIZE,
            "vault event collection exceeds the size limit"
        );
        let mut decoder = Decoder::new(bytes);
        ensure!(decoder.take(8)? == LOG_MAGIC, "invalid vault log magic");
        let mut events = Vec::new();
        let mut diagnostics = Vec::new();
        let mut hashes = BTreeSet::new();
        let mut record = 0usize;
        while !decoder.is_empty() {
            record += 1;
            let length = decoder
                .u32()
                .with_context(|| format!("truncated event length at record {record}"))?
                as usize;
            ensure!(
                length <= MAX_EVENT_SIZE,
                "event {record} exceeds the size limit"
            );
            let bytes = decoder
                .take(length)
                .with_context(|| format!("truncated event at record {record}"))?;
            match Event::decode(bytes) {
                Ok(event) => {
                    let hash = event.verified_event_hash()?;
                    if !hashes.insert(hash) {
                        diagnostics.push(format!(
                            "record {record}: duplicate event hash {} ignored",
                            hex::encode_upper(&hash[..8])
                        ));
                        continue;
                    }
                    events.push(event);
                }
                Err(error) => diagnostics.push(format!("record {record}: {error:#}")),
            }
        }
        Ok(Self {
            events,
            diagnostics,
        })
    }

    pub fn append(&mut self, event: Event) -> Result<()> {
        event.verify_structure()?;
        let hash = event.verified_event_hash()?;
        if self
            .events
            .iter()
            .any(|item| item.verified_event_hash().ok() == Some(hash))
        {
            return Ok(());
        }
        self.events.push(event);
        ensure!(
            self.encode()?.len() <= MAX_LOG_SIZE,
            "vault event collection exceeds the size limit"
        );
        Ok(())
    }

    pub fn union(&self, other: &Self) -> Result<Self> {
        let local_root = self.genesis_hash()?;
        let remote_root = other.genesis_hash()?;
        if let (Some(local), Some(remote)) = (local_root, remote_root) {
            ensure!(
                local == remote,
                "local and fetched event collections have different Genesis events"
            );
        }
        let root = local_root.or(remote_root);
        let mut by_hash = std::collections::BTreeMap::new();
        for event in self.events.iter().chain(&other.events) {
            event.verify_structure()?;
            by_hash
                .entry(event.verified_event_hash()?)
                .or_insert_with(|| event.clone());
        }
        let mut events = Vec::with_capacity(by_hash.len());
        if let Some(root) = root {
            if let Some(event) = by_hash.remove(&root) {
                events.push(event);
            }
        }
        events.extend(by_hash.into_values());
        let mut diagnostics = self.diagnostics.clone();
        diagnostics.extend(other.diagnostics.iter().cloned());
        diagnostics.sort();
        diagnostics.dedup();
        let merged = Self {
            events,
            diagnostics,
        };
        ensure!(
            merged.encode()?.len() <= MAX_LOG_SIZE,
            "merged event collection exceeds the size limit"
        );
        Ok(merged)
    }

    fn genesis_hash(&self) -> Result<Option<Hash>> {
        self.events
            .iter()
            .find(|event| matches!(event.payload, EventPayload::Genesis(_)))
            .map(Event::verified_event_hash)
            .transpose()
    }
}

fn put_event_record(output: &mut Vec<u8>, event: &Event) -> Result<()> {
    let encoded = event.encode()?;
    put_u32(output, encoded.len())?;
    output.extend_from_slice(&encoded);
    Ok(())
}

fn validate_payload(payload: &EventPayload) -> Result<()> {
    match payload {
        EventPayload::Genesis(epoch) | EventPayload::MembershipEpoch(epoch) => {
            validate_epoch(epoch)?
        }
        EventPayload::Mutation {
            parents,
            ciphertext,
            ..
        } => {
            ensure!(
                parents.len() <= MAX_MUTATION_PARENTS,
                "too many mutation parents"
            );
            let mut unique = BTreeSet::new();
            ensure!(
                parents.iter().all(|parent| unique.insert(*parent)),
                "duplicate mutation parent"
            );
            ensure!(
                !ciphertext.is_empty() && ciphertext.len() <= MAX_VALUE_SIZE + MAX_KEY_LEN + 64,
                "invalid encrypted mutation size"
            );
        }
    }
    Ok(())
}

fn validate_epoch(epoch: &MembershipEpoch) -> Result<()> {
    ensure!(epoch.epoch_number > 0, "membership epoch must be positive");
    ensure!(
        epoch.previous_epoch_heads.len() <= MAX_MUTATION_PARENTS,
        "too many preceding mutation heads"
    );
    let mut unique_heads = BTreeSet::new();
    ensure!(
        epoch
            .previous_epoch_heads
            .iter()
            .all(|head| unique_heads.insert(*head)),
        "duplicate preceding mutation head"
    );
    ensure!(!epoch.members.is_empty(), "membership epoch has no members");
    ensure!(epoch.members.len() <= MAX_MEMBERS, "too many members");
    ensure!(
        epoch
            .members
            .iter()
            .any(|member| member.role == Role::Owner),
        "membership epoch has no owner"
    );
    ensure!(
        !epoch.snapshot.ciphertext.is_empty()
            && epoch.snapshot.ciphertext.len() <= MAX_VALUE_SIZE + 16,
        "invalid encrypted snapshot size"
    );
    let mut signing_keys = BTreeSet::new();
    let mut encryption_keys = BTreeSet::new();
    for member in &epoch.members {
        validate_member_identity(&member.identity)?;
        ensure!(
            signing_keys.insert(member.identity.signing_public_key),
            "duplicate member signing key"
        );
        ensure!(
            encryption_keys.insert(member.identity.encryption_public_key),
            "duplicate member encryption key"
        );
        ensure!(
            member.wrapped_epoch_key.ciphertext.len() == 48,
            "invalid wrapped epoch key size"
        );
    }
    Ok(())
}

fn validate_member_identity(identity: &MemberIdentity) -> Result<()> {
    validate_string(&identity.name, MAX_NAME_LEN, "member name")?;
    VerifyingKey::from_bytes(&identity.signing_public_key).context("invalid member Ed25519 key")?;
    Ok(())
}

fn validate_string(value: &str, limit: usize, field: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{field} cannot be empty");
    ensure!(value.len() <= limit, "{field} is too long");
    ensure!(!value.contains('\0'), "{field} contains a NUL byte");
    Ok(())
}

fn encode_payload(payload: &EventPayload) -> Result<Vec<u8>> {
    validate_payload(payload)?;
    let mut output = Vec::new();
    match payload {
        EventPayload::Genesis(epoch) | EventPayload::MembershipEpoch(epoch) => {
            encode_epoch(&mut output, epoch)?;
        }
        EventPayload::Mutation {
            epoch_number,
            parents,
            nonce,
            ciphertext,
        } => {
            put_u64(&mut output, *epoch_number);
            put_u16(&mut output, parents.len() as u16);
            for parent in parents {
                output.extend_from_slice(parent);
            }
            output.extend_from_slice(nonce);
            put_bytes(&mut output, ciphertext)?;
        }
    }
    Ok(output)
}

fn decode_payload(type_code: u16, bytes: &[u8]) -> Result<EventPayload> {
    let mut decoder = Decoder::new(bytes);
    let payload = match type_code {
        1 => EventPayload::Genesis(decode_epoch(&mut decoder)?),
        2 => EventPayload::MembershipEpoch(decode_epoch(&mut decoder)?),
        3 => {
            let epoch_number = decoder.u64()?;
            let count = decoder.u16()? as usize;
            ensure!(count <= MAX_MUTATION_PARENTS, "too many mutation parents");
            let mut parents = Vec::with_capacity(count);
            for _ in 0..count {
                parents.push(decoder.array()?);
            }
            EventPayload::Mutation {
                epoch_number,
                parents,
                nonce: decoder.array()?,
                ciphertext: decoder
                    .bytes(MAX_VALUE_SIZE + MAX_KEY_LEN + 64, "encrypted mutation")?,
            }
        }
        _ => bail!("unknown event type {type_code}"),
    };
    decoder.finish()?;
    validate_payload(&payload)?;
    Ok(payload)
}

fn encode_epoch(output: &mut Vec<u8>, epoch: &MembershipEpoch) -> Result<()> {
    put_u64(output, epoch.epoch_number);
    put_u16(output, epoch.previous_epoch_heads.len() as u16);
    for head in &epoch.previous_epoch_heads {
        output.extend_from_slice(head);
    }
    put_u16(output, epoch.members.len() as u16);
    for member in &epoch.members {
        encode_member_identity(output, &member.identity)?;
        output.push(member.role.encode());
        output.extend_from_slice(&member.wrapped_epoch_key.ephemeral_public_key);
        output.extend_from_slice(&member.wrapped_epoch_key.nonce);
        put_bytes(output, &member.wrapped_epoch_key.ciphertext)?;
    }
    output.extend_from_slice(&epoch.snapshot.nonce);
    put_bytes(output, &epoch.snapshot.ciphertext)?;
    Ok(())
}

fn decode_epoch(decoder: &mut Decoder<'_>) -> Result<MembershipEpoch> {
    let epoch_number = decoder.u64()?;
    let head_count = decoder.u16()? as usize;
    ensure!(
        head_count <= MAX_MUTATION_PARENTS,
        "too many preceding mutation heads"
    );
    let mut previous_epoch_heads = Vec::with_capacity(head_count);
    for _ in 0..head_count {
        previous_epoch_heads.push(decoder.array()?);
    }
    let count = decoder.u16()? as usize;
    ensure!(count <= MAX_MEMBERS, "too many members");
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        members.push(EpochMember {
            identity: decode_member_identity(decoder)?,
            role: Role::decode(decoder.u8()?)?,
            wrapped_epoch_key: WrappedEpochKey {
                ephemeral_public_key: decoder.array()?,
                nonce: decoder.array()?,
                ciphertext: decoder.bytes(48, "wrapped epoch key")?,
            },
        });
    }
    let snapshot = EncryptedSnapshot {
        nonce: decoder.array()?,
        ciphertext: decoder.bytes(MAX_VALUE_SIZE + 16, "encrypted snapshot")?,
    };
    Ok(MembershipEpoch {
        epoch_number,
        members,
        snapshot,
        previous_epoch_heads,
    })
}

fn encode_member_identity(output: &mut Vec<u8>, identity: &MemberIdentity) -> Result<()> {
    put_string(output, &identity.name)?;
    output.extend_from_slice(&identity.signing_public_key);
    output.extend_from_slice(&identity.encryption_public_key);
    Ok(())
}

fn decode_member_identity(decoder: &mut Decoder<'_>) -> Result<MemberIdentity> {
    Ok(MemberIdentity {
        name: decoder.string(MAX_NAME_LEN, "member name")?,
        signing_public_key: decoder.array()?,
        encryption_public_key: decoder.array()?,
    })
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).context("encoded field is too large")?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_u32(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    put_bytes(output, value.as_bytes())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("encoded length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated encoding")?;
        self.offset = end;
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

    fn bytes(&mut self, limit: usize, field: &str) -> Result<Vec<u8>> {
        let length = self.u32()? as usize;
        ensure!(length <= limit, "{field} is too large");
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, limit: usize, field: &str) -> Result<String> {
        let bytes = self.bytes(limit, field)?;
        String::from_utf8(bytes).with_context(|| format!("{field} is not UTF-8"))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn finish(&self) -> Result<()> {
        ensure!(self.is_empty(), "trailing data in canonical encoding");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::identity::{DeviceIdentity, IdentityBackend, IdentitySession};

    struct TestSession {
        identity: DeviceIdentity,
        signing: SigningKey,
    }

    impl IdentitySession for TestSession {
        fn identity(&self) -> &DeviceIdentity {
            &self.identity
        }

        fn sign(&mut self, message: &[u8; 32]) -> Result<[u8; 64]> {
            Ok(self.signing.sign(message).to_bytes())
        }

        fn agree(&mut self, _peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
            unreachable!()
        }
    }

    fn signed_event() -> Event {
        signed_event_with_marker(4)
    }

    fn signed_event_with_marker(marker: u8) -> Event {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let identity = DeviceIdentity {
            backend: IdentityBackend::TouchId,
            locator: "1".into(),
            display_name: "Test".into(),
            encryption_public_key: [8; 32],
            signing_public_key: signing.verifying_key().to_bytes(),
        };
        let mut session = TestSession { identity, signing };
        Event::unsigned(
            [1; 32],
            [2; 32],
            session.identity.signing_public_key,
            EventPayload::Mutation {
                epoch_number: 1,
                parents: Vec::new(),
                nonce: [3; 12],
                ciphertext: vec![marker; 16],
            },
        )
        .sign(&mut session)
        .unwrap()
    }

    #[test]
    fn event_and_log_round_trip_canonically() {
        let event = signed_event();
        let encoded = event.encode().unwrap();
        assert_eq!(Event::decode(&encoded).unwrap(), event);
        let log = EventLog {
            events: vec![event],
            diagnostics: Vec::new(),
        };
        let encoded = log.encode().unwrap();
        let decoded = EventLog::decode(&encoded).unwrap();
        assert_eq!(decoded.events, log.events);
        assert_eq!(decoded.diagnostics, log.diagnostics);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn rejects_truncation_trailing_data_and_corrupt_signature() {
        let event = signed_event();
        let encoded = event.encode().unwrap();
        assert!(Event::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Event::decode(&trailing).is_err());
        let mut corrupt = encoded;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(Event::decode(&corrupt).is_err());
    }

    #[test]
    fn invalid_record_does_not_desynchronize_following_event() {
        let valid = signed_event().encode().unwrap();
        let mut bytes = LOG_MAGIC.to_vec();
        put_u32(&mut bytes, 3).unwrap();
        bytes.extend_from_slice(b"bad");
        put_u32(&mut bytes, valid.len()).unwrap();
        bytes.extend_from_slice(&valid);
        let mut log = EventLog::decode(&bytes).unwrap();
        assert_eq!(log.events.len(), 1);
        assert_eq!(log.diagnostics.len(), 1);

        log.append(signed_event_with_marker(5)).unwrap();
        let appended = log.encode().unwrap();
        let decoded = EventLog::decode(&appended).unwrap();
        assert_eq!(decoded.events.len(), 2);
        assert!(decoded.diagnostics.is_empty());
        assert!(!appended.windows(3).any(|window| window == b"bad"));
    }

    #[test]
    fn duplicate_hashes_are_diagnostic_and_oversized_records_are_rejected() {
        let valid = signed_event().encode().unwrap();
        let mut duplicate = LOG_MAGIC.to_vec();
        for _ in 0..2 {
            put_u32(&mut duplicate, valid.len()).unwrap();
            duplicate.extend_from_slice(&valid);
        }
        let decoded = EventLog::decode(&duplicate).unwrap();
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.diagnostics.len(), 1);

        let mut oversized = LOG_MAGIC.to_vec();
        put_u32(&mut oversized, MAX_EVENT_SIZE + 1).unwrap();
        assert!(EventLog::decode(&oversized).is_err());
    }

    #[test]
    fn event_collection_union_is_commutative_and_preserves_candidates() {
        let first = signed_event();
        let second = signed_event_with_marker(5);
        let left = EventLog {
            events: vec![first.clone()],
            diagnostics: Vec::new(),
        };
        let right = EventLog {
            events: vec![second.clone()],
            diagnostics: Vec::new(),
        };
        let merged_left = left.union(&right).unwrap();
        let merged_right = right.union(&left).unwrap();
        assert_eq!(merged_left.events.len(), 2);
        assert_eq!(
            merged_left.encode().unwrap(),
            merged_right.encode().unwrap()
        );
        assert!(merged_left.events.contains(&first));
        assert!(merged_left.events.contains(&second));
    }
}
