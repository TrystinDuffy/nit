use std::collections::BTreeSet;

use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::identity::IdentitySession;

pub type Hash = [u8; 32];
pub type VaultId = [u8; 32];
pub type EventId = [u8; 16];

pub const LOG_MAGIC: &[u8; 8] = b"GVLOG002";
pub const EVENT_MAGIC: &[u8; 8] = b"GVEVT002";
pub const FORMAT_VERSION: u16 = 2;
pub const MAX_EVENT_SIZE: usize = 20 * 1024 * 1024;
pub const MAX_LOG_SIZE: usize = 64 * 1024 * 1024;
pub const MAX_MEMBERS: usize = 64;
pub const MAX_INVITATIONS: usize = 32;
pub const MAX_PROPOSALS: usize = 128;
pub const MAX_KEY_LEN: usize = 1_024;
pub const MAX_VALUE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_CERTIFICATE_SIZE: usize = 16 * 1024;
pub const MAX_PAKE_MESSAGE_SIZE: usize = 64 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"git-vault/event-signature/v1";
const EVENT_HASH_DOMAIN: &[u8] = b"git-vault/event-hash/v1";
const ADMISSION_BINDING_DOMAIN: &[u8] = b"git-vault/admission-binding/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Reader,
    Owner,
}

impl Role {
    fn encode(self) -> u8 {
        match self {
            Self::Reader => 1,
            Self::Owner => 2,
        }
    }

    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Reader),
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
    pub certificate: Vec<u8>,
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
    pub accepted_proposal: Option<Hash>,
    pub admission_confirmation: Option<Hash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    Text,
    Number,
    Boolean,
    Bytes,
}

impl ValueType {
    fn encode(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Number => 2,
            Self::Boolean => 3,
            Self::Bytes => 4,
        }
    }

    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Text),
            2 => Ok(Self::Number),
            3 => Ok(Self::Boolean),
            4 => Ok(Self::Bytes),
            _ => bail!("unknown value type {value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventPayload {
    Genesis(MembershipEpoch),
    MembershipEpoch(MembershipEpoch),
    Put {
        epoch_number: u64,
        key: String,
        value_type: ValueType,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
    Delete {
        epoch_number: u64,
        key: String,
    },
    CreateInvitation {
        epoch_number: u64,
        invitation_id: [u8; 16],
        expires_at: u64,
        pake_message: Vec<u8>,
    },
    CloseInvitation {
        invitation_id: [u8; 16],
    },
    InvitationResponse {
        epoch_number: u64,
        invitation_id: [u8; 16],
        proposal_event_hash: Hash,
        pake_message: Vec<u8>,
    },
    ProposeUser {
        invitation_id: [u8; 16],
        identity: MemberIdentity,
        response_event_hash: Option<Hash>,
        pake_message: Vec<u8>,
    },
    Unknown {
        type_code: u16,
        bytes: Vec<u8>,
    },
}

impl EventPayload {
    pub fn type_code(&self) -> u16 {
        match self {
            Self::Genesis(_) => 1,
            Self::MembershipEpoch(_) => 2,
            Self::Put { .. } => 3,
            Self::Delete { .. } => 4,
            Self::CreateInvitation { .. } => 5,
            Self::CloseInvitation { .. } => 6,
            Self::ProposeUser { .. } => 7,
            Self::InvitationResponse { .. } => 8,
            Self::Unknown { type_code, .. } => *type_code,
        }
    }

    pub fn is_trust_state_changing(&self) -> bool {
        !matches!(self, Self::ProposeUser { .. } | Self::Unknown { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub vault_id: VaultId,
    pub event_id: EventId,
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
        let mut event_id = [0u8; 16];
        OsRng.fill_bytes(&mut event_id);
        Self {
            vault_id,
            event_id,
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
        let mut hasher = Sha256::new();
        hasher.update(EVENT_HASH_DOMAIN);
        hasher.update(self.encode_without_signature()?);
        hasher.update(self.signature);
        Ok(hasher.finalize().into())
    }

    pub fn verify_structure(&self) -> Result<()> {
        ensure!(self.vault_id != [0; 32], "vault ID cannot be zero");
        ensure!(self.event_id != [0; 16], "event ID cannot be zero");
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
        let mut output = Vec::with_capacity(134 + payload.len());
        output.extend_from_slice(EVENT_MAGIC);
        put_u16(&mut output, FORMAT_VERSION);
        output.extend_from_slice(&self.vault_id);
        output.extend_from_slice(&self.event_id);
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
        let event_id = decoder.array()?;
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
            event_id,
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
    raw_records: Vec<Vec<u8>>,
}

impl EventLog {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        output.extend_from_slice(LOG_MAGIC);
        if self.raw_records.is_empty() {
            for event in &self.events {
                let encoded = event.encode()?;
                put_u32(&mut output, encoded.len())?;
                output.extend_from_slice(&encoded);
            }
        } else {
            for record in &self.raw_records {
                ensure!(
                    record.len() <= MAX_EVENT_SIZE,
                    "event exceeds the size limit"
                );
                put_u32(&mut output, record.len())?;
                output.extend_from_slice(record);
            }
        }
        ensure!(
            output.len() <= MAX_LOG_SIZE,
            "vault log exceeds the size limit"
        );
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_LOG_SIZE,
            "vault log exceeds the size limit"
        );
        let mut decoder = Decoder::new(bytes);
        ensure!(decoder.take(8)? == LOG_MAGIC, "invalid vault log magic");
        let mut events = Vec::new();
        let mut diagnostics = Vec::new();
        let mut raw_records = Vec::new();
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
            raw_records.push(bytes.to_vec());
            match Event::decode(bytes) {
                Ok(event) => events.push(event),
                Err(error) => diagnostics.push(format!("record {record}: {error:#}")),
            }
        }
        let mut ids = BTreeSet::new();
        for event in &events {
            ensure!(
                ids.insert(event.event_id),
                "duplicate event ID in vault log"
            );
        }
        Ok(Self {
            events,
            diagnostics,
            raw_records,
        })
    }

    pub fn append(&mut self, event: Event) -> Result<()> {
        event.verify_structure()?;
        ensure!(
            !self
                .events
                .iter()
                .any(|item| item.event_id == event.event_id),
            "duplicate event ID"
        );
        if self.raw_records.is_empty() && !self.events.is_empty() {
            self.raw_records = self
                .events
                .iter()
                .map(Event::encode)
                .collect::<Result<Vec<_>>>()?;
        }
        self.raw_records.push(event.encode()?);
        self.events.push(event);
        ensure!(
            self.encode()?.len() <= MAX_LOG_SIZE,
            "vault log exceeds the size limit"
        );
        Ok(())
    }
}

pub fn admission_binding_digest(
    vault_id: &VaultId,
    parent_trust_hash: &Hash,
    epoch: &MembershipEpoch,
) -> Result<Hash> {
    let proposal = epoch
        .accepted_proposal
        .context("admission epoch has no accepted proposal")?;
    let mut unconfirmed = epoch.clone();
    unconfirmed.admission_confirmation = None;
    let mut encoded = Vec::new();
    encode_epoch(&mut encoded, &unconfirmed)?;
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_BINDING_DOMAIN);
    hasher.update(vault_id);
    hasher.update(parent_trust_hash);
    hasher.update(proposal);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn validate_payload(payload: &EventPayload) -> Result<()> {
    match payload {
        EventPayload::Genesis(epoch) | EventPayload::MembershipEpoch(epoch) => {
            validate_epoch(epoch)?
        }
        EventPayload::Put {
            key, ciphertext, ..
        } => {
            validate_key(key)?;
            ensure!(!ciphertext.is_empty(), "encrypted value cannot be empty");
            ensure!(
                ciphertext.len() <= MAX_VALUE_SIZE + 16,
                "encrypted value is too large"
            );
        }
        EventPayload::Delete { key, .. } => validate_key(key)?,
        EventPayload::CreateInvitation {
            invitation_id,
            pake_message,
            ..
        }
        | EventPayload::InvitationResponse {
            invitation_id,
            pake_message,
            ..
        }
        | EventPayload::ProposeUser {
            invitation_id,
            pake_message,
            ..
        } => {
            ensure!(*invitation_id != [0; 16], "invitation ID cannot be zero");
            ensure!(
                pake_message.len() <= MAX_PAKE_MESSAGE_SIZE,
                "PAKE message is too large"
            );
        }
        EventPayload::CloseInvitation { invitation_id } => {
            ensure!(*invitation_id != [0; 16], "invitation ID cannot be zero");
        }
        EventPayload::Unknown { type_code, .. } => ensure!(
            !(1..=8).contains(type_code),
            "unknown event payload uses a reserved type code"
        ),
    }
    if let EventPayload::ProposeUser { identity, .. } = payload {
        validate_member_identity(identity)?;
    }
    Ok(())
}

fn validate_epoch(epoch: &MembershipEpoch) -> Result<()> {
    ensure!(
        epoch.accepted_proposal.is_some() == epoch.admission_confirmation.is_some(),
        "accepted proposal and admission confirmation must appear together"
    );
    ensure!(epoch.epoch_number > 0, "membership epoch must be positive");
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
    ensure!(
        identity.certificate.len() <= MAX_CERTIFICATE_SIZE,
        "device certificate is too large"
    );
    ensure!(
        identity.certificate.is_empty(),
        "device certificates are not accepted until X.509 binding verification is implemented"
    );
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    validate_string(key, MAX_KEY_LEN, "secret key")
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
        EventPayload::Put {
            epoch_number,
            key,
            value_type,
            nonce,
            ciphertext,
        } => {
            put_u64(&mut output, *epoch_number);
            put_string(&mut output, key)?;
            output.push(value_type.encode());
            output.extend_from_slice(nonce);
            put_bytes(&mut output, ciphertext)?;
        }
        EventPayload::Delete { epoch_number, key } => {
            put_u64(&mut output, *epoch_number);
            put_string(&mut output, key)?;
        }
        EventPayload::CreateInvitation {
            epoch_number,
            invitation_id,
            expires_at,
            pake_message,
        } => {
            put_u64(&mut output, *epoch_number);
            output.extend_from_slice(invitation_id);
            put_u64(&mut output, *expires_at);
            put_bytes(&mut output, pake_message)?;
        }
        EventPayload::CloseInvitation { invitation_id } => {
            output.extend_from_slice(invitation_id);
        }
        EventPayload::InvitationResponse {
            epoch_number,
            invitation_id,
            proposal_event_hash,
            pake_message,
        } => {
            put_u64(&mut output, *epoch_number);
            output.extend_from_slice(invitation_id);
            output.extend_from_slice(proposal_event_hash);
            put_bytes(&mut output, pake_message)?;
        }
        EventPayload::ProposeUser {
            invitation_id,
            identity,
            response_event_hash,
            pake_message,
        } => {
            output.extend_from_slice(invitation_id);
            encode_member_identity(&mut output, identity)?;
            put_optional_hash(&mut output, response_event_hash);
            put_bytes(&mut output, pake_message)?;
        }
        EventPayload::Unknown { bytes, .. } => output.extend_from_slice(bytes),
    }
    Ok(output)
}

fn decode_payload(type_code: u16, bytes: &[u8]) -> Result<EventPayload> {
    let mut decoder = Decoder::new(bytes);
    let payload = match type_code {
        1 => EventPayload::Genesis(decode_epoch(&mut decoder)?),
        2 => EventPayload::MembershipEpoch(decode_epoch(&mut decoder)?),
        3 => EventPayload::Put {
            epoch_number: decoder.u64()?,
            key: decoder.string(MAX_KEY_LEN, "secret key")?,
            value_type: ValueType::decode(decoder.u8()?)?,
            nonce: decoder.array()?,
            ciphertext: decoder.bytes(MAX_VALUE_SIZE + 16, "encrypted value")?,
        },
        4 => EventPayload::Delete {
            epoch_number: decoder.u64()?,
            key: decoder.string(MAX_KEY_LEN, "secret key")?,
        },
        5 => EventPayload::CreateInvitation {
            epoch_number: decoder.u64()?,
            invitation_id: decoder.array()?,
            expires_at: decoder.u64()?,
            pake_message: decoder.bytes(MAX_PAKE_MESSAGE_SIZE, "PAKE message")?,
        },
        6 => EventPayload::CloseInvitation {
            invitation_id: decoder.array()?,
        },
        7 => EventPayload::ProposeUser {
            invitation_id: decoder.array()?,
            identity: decode_member_identity(&mut decoder)?,
            response_event_hash: decoder.optional_hash("proposal response")?,
            pake_message: decoder.bytes(MAX_PAKE_MESSAGE_SIZE, "PAKE message")?,
        },
        8 => EventPayload::InvitationResponse {
            epoch_number: decoder.u64()?,
            invitation_id: decoder.array()?,
            proposal_event_hash: decoder.array()?,
            pake_message: decoder.bytes(MAX_PAKE_MESSAGE_SIZE, "PAKE message")?,
        },
        _ => {
            return Ok(EventPayload::Unknown {
                type_code,
                bytes: bytes.to_vec(),
            });
        }
    };
    decoder.finish()?;
    validate_payload(&payload)?;
    Ok(payload)
}

fn encode_epoch(output: &mut Vec<u8>, epoch: &MembershipEpoch) -> Result<()> {
    put_u64(output, epoch.epoch_number);
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
    put_optional_hash(output, &epoch.accepted_proposal);
    put_optional_hash(output, &epoch.admission_confirmation);
    Ok(())
}

fn decode_epoch(decoder: &mut Decoder<'_>) -> Result<MembershipEpoch> {
    let epoch_number = decoder.u64()?;
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
    let accepted_proposal = decoder.optional_hash("accepted proposal")?;
    let admission_confirmation = decoder.optional_hash("admission confirmation")?;
    Ok(MembershipEpoch {
        epoch_number,
        members,
        snapshot,
        accepted_proposal,
        admission_confirmation,
    })
}

fn encode_member_identity(output: &mut Vec<u8>, identity: &MemberIdentity) -> Result<()> {
    put_string(output, &identity.name)?;
    output.extend_from_slice(&identity.signing_public_key);
    output.extend_from_slice(&identity.encryption_public_key);
    put_bytes(output, &identity.certificate)?;
    Ok(())
}

fn decode_member_identity(decoder: &mut Decoder<'_>) -> Result<MemberIdentity> {
    Ok(MemberIdentity {
        name: decoder.string(MAX_NAME_LEN, "member name")?,
        signing_public_key: decoder.array()?,
        encryption_public_key: decoder.array()?,
        certificate: decoder.bytes(MAX_CERTIFICATE_SIZE, "device certificate")?,
    })
}

fn put_optional_hash(output: &mut Vec<u8>, value: &Option<Hash>) {
    match value {
        Some(hash) => {
            output.push(1);
            output.extend_from_slice(hash);
        }
        None => output.push(0),
    }
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

    fn optional_hash(&mut self, field: &str) -> Result<Option<Hash>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.array()?)),
            value => bail!("invalid {field} marker {value}"),
        }
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
    use crate::identity::{DeviceIdentity, IdentitySession};

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
        let signing = SigningKey::from_bytes(&[7; 32]);
        let identity = DeviceIdentity {
            backend: "test".into(),
            locator: "1".into(),
            display_name: "Test".into(),
            encryption_public_key: [8; 32],
            signing_public_key: signing.verifying_key().to_bytes(),
            certificate: Vec::new(),
        };
        let mut session = TestSession { identity, signing };
        Event::unsigned(
            [1; 32],
            [2; 32],
            session.identity.signing_public_key,
            EventPayload::Delete {
                epoch_number: 1,
                key: "TOKEN".into(),
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
            raw_records: Vec::new(),
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

        log.append(signed_event()).unwrap();
        let appended = log.encode().unwrap();
        let decoded = EventLog::decode(&appended).unwrap();
        assert_eq!(decoded.events.len(), 2);
        assert_eq!(decoded.diagnostics.len(), 1);
        assert!(appended.windows(3).any(|window| window == b"bad"));
    }

    #[test]
    fn duplicate_ids_and_oversized_records_are_rejected() {
        let valid = signed_event().encode().unwrap();
        let mut duplicate = LOG_MAGIC.to_vec();
        for _ in 0..2 {
            put_u32(&mut duplicate, valid.len()).unwrap();
            duplicate.extend_from_slice(&valid);
        }
        assert!(EventLog::decode(&duplicate).is_err());

        let mut oversized = LOG_MAGIC.to_vec();
        put_u32(&mut oversized, MAX_EVENT_SIZE + 1).unwrap();
        assert!(EventLog::decode(&oversized).is_err());
    }

    #[test]
    fn unknown_signed_event_is_structurally_valid_but_inert() {
        let signing = SigningKey::from_bytes(&[11; 32]);
        let identity = DeviceIdentity {
            backend: "test".into(),
            locator: "unknown".into(),
            display_name: "Unknown".into(),
            encryption_public_key: [12; 32],
            signing_public_key: signing.verifying_key().to_bytes(),
            certificate: Vec::new(),
        };
        let mut session = TestSession { identity, signing };
        let event = Event::unsigned(
            [1; 32],
            [2; 32],
            session.identity.signing_public_key,
            EventPayload::Unknown {
                type_code: 65_000,
                bytes: vec![1, 2, 3],
            },
        )
        .sign(&mut session)
        .unwrap();
        let decoded = Event::decode(&event.encode().unwrap()).unwrap();
        assert_eq!(decoded, event);
        assert!(!decoded.payload.is_trust_state_changing());
    }
}
