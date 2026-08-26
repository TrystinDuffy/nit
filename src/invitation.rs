use anyhow::{ensure, Context, Result};
use bip39::Language;
use hmac::{Hmac, Mac};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{decrypt_protocol_state, encrypt_protocol_state, EpochKey, ProtocolStateContext},
    event::{admission_binding_digest, Hash, MemberIdentity, MembershipEpoch, VaultId},
    state::{InvitationState, ProposalAuthentication},
};

const INVITATION_MAGIC: &[u8; 8] = b"GVSPKIN1";
const OWNER_STATE_MAGIC: &[u8; 8] = b"GVSPKOS1";
const REPLY_MAGIC: &[u8; 8] = b"GVSPKRP1";
const SESSION_STATE_MAGIC: &[u8; 8] = b"GVSPKSK1";
const OWNER_STATE_PURPOSE: &[u8] = b"spake2-owner-state";
const IDENTITY_DOMAIN: &[u8] = b"git-vault/spake2-identities/v1";
const REQUESTER_CONFIRMATION_DOMAIN: &[u8] = b"git-vault/spake2-requester-confirmation/v1";
const ADMISSION_CONFIRMATION_DOMAIN: &[u8] = b"git-vault/spake2-admission-confirmation/v1";
const MAX_PAKE_FIELD: usize = 64 * 1024;
const SPAKE_MESSAGE_SIZE: usize = 33;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientSessionState {
    pub invitation_id: [u8; 16],
    pub invitation_event_hash: Hash,
    pub final_proposal_hash: Hash,
    pub proposal_identity: MemberIdentity,
    pub session_key: Zeroizing<Vec<u8>>,
}

pub fn generate_phrase(words: usize) -> Result<Zeroizing<String>> {
    ensure!(
        (4..=6).contains(&words),
        "invitation phrase must contain 4–6 words"
    );
    let list = Language::English.word_list();
    let mut selected = Vec::with_capacity(words);
    for _ in 0..words {
        selected.push(list[(OsRng.next_u32() as usize) & 0x7ff]);
    }
    Ok(Zeroizing::new(selected.join(" ")))
}

pub fn validate_phrase(phrase: &str) -> Result<()> {
    let words = phrase.split_whitespace().collect::<Vec<_>>();
    ensure!(
        (4..=6).contains(&words.len()),
        "invitation phrase must contain 4–6 words"
    );
    let list = Language::English.word_list();
    ensure!(
        words.iter().all(|word| list.binary_search(word).is_ok()),
        "invitation phrase contains a word outside the BIP-39 English list"
    );
    ensure!(
        phrase == words.join(" "),
        "invitation phrase must use single spaces"
    );
    Ok(())
}

/// Creates the owner's SPAKE2 challenge and encrypts the resumable owner state.
pub fn create_registration(
    vault_id: &VaultId,
    epoch_number: u64,
    parent_trust_hash: &Hash,
    invitation_id: &[u8; 16],
    phrase: &str,
    epoch_key: &EpochKey,
) -> Result<Vec<u8>> {
    validate_phrase(phrase)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    let (requester_id, owner_id) = spake_identities(vault_id, invitation_id, parent_trust_hash);
    let (_, owner_message) = Spake2::<Ed25519Group>::start_b_with_rng(
        &Password::new(phrase.as_bytes()),
        &Identity::new(&requester_id),
        &Identity::new(&owner_id),
        ChaCha20Rng::from_seed(*seed),
    );
    ensure!(
        owner_message.len() == SPAKE_MESSAGE_SIZE,
        "SPAKE2 produced an invalid owner challenge"
    );

    let mut owner_state = Zeroizing::new(OWNER_STATE_MAGIC.to_vec());
    owner_state.extend_from_slice(seed.as_ref());
    put_bytes(&mut owner_state, phrase.as_bytes())?;
    let (nonce, encrypted_owner_state) = encrypt_protocol_state(
        &ProtocolStateContext {
            vault_id,
            epoch_number,
            invitation_id,
            reference_hash: parent_trust_hash,
            purpose: OWNER_STATE_PURPOSE,
        },
        &owner_state,
        epoch_key,
    )?;
    owner_state.zeroize();
    seed.zeroize();

    let mut output = INVITATION_MAGIC.to_vec();
    put_bytes(&mut output, &owner_message)?;
    output.extend_from_slice(&nonce);
    put_bytes(&mut output, &encrypted_owner_state)?;
    ensure!(
        output.len() <= MAX_PAKE_FIELD,
        "SPAKE2 invitation record is too large"
    );
    Ok(output)
}

/// Solves the invitation challenge and creates a requester-confirmed join proof.
pub fn start_proposal(
    vault_id: &VaultId,
    invitation: &InvitationState,
    identity: &MemberIdentity,
    phrase: &str,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    validate_phrase(phrase)?;
    let record = decode_invitation(&invitation.pake_message)?;
    let (requester_id, owner_id) = spake_identities(
        vault_id,
        &invitation.invitation_id,
        &invitation.create_parent_trust_hash,
    );
    let (requester, requester_message) = Spake2::<Ed25519Group>::start_a(
        &Password::new(phrase.as_bytes()),
        &Identity::new(&requester_id),
        &Identity::new(&owner_id),
    );
    let session_key = Zeroizing::new(
        requester
            .finish(&record.owner_message)
            .map_err(|error| anyhow::anyhow!("invalid SPAKE2 owner challenge: {error:?}"))?,
    );
    let confirmation = requester_confirmation(
        &session_key,
        vault_id,
        invitation,
        identity,
        &requester_message,
        &record.owner_message,
    )?;
    let mut reply = REPLY_MAGIC.to_vec();
    put_bytes(&mut reply, &requester_message)?;
    reply.extend_from_slice(&confirmation);
    Ok((reply, session_key))
}

/// Verifies the requester's SPAKE2 solution. A wrong phrase produces a different
/// session key and therefore fails explicit requester key confirmation.
pub fn authenticate_proposal(
    vault_id: &VaultId,
    invitation: &InvitationState,
    reply: &[u8],
    proposal_identity: &MemberIdentity,
    epoch_key: &EpochKey,
) -> Result<(ProposalAuthentication, Zeroizing<Vec<u8>>)> {
    let invitation_record = decode_invitation(&invitation.pake_message)?;
    let reply = decode_reply(reply)?;
    let owner_state = decrypt_protocol_state(
        &ProtocolStateContext {
            vault_id,
            epoch_number: invitation.epoch_number,
            invitation_id: &invitation.invitation_id,
            reference_hash: &invitation.create_parent_trust_hash,
            purpose: OWNER_STATE_PURPOSE,
        },
        &invitation_record.state_nonce,
        &invitation_record.encrypted_owner_state,
        epoch_key,
    )?;
    let (seed, phrase) = decode_owner_state(&owner_state)?;
    let (requester_id, owner_id) = spake_identities(
        vault_id,
        &invitation.invitation_id,
        &invitation.create_parent_trust_hash,
    );
    let (owner, reconstructed_challenge) = Spake2::<Ed25519Group>::start_b_with_rng(
        &Password::new(&phrase),
        &Identity::new(&requester_id),
        &Identity::new(&owner_id),
        ChaCha20Rng::from_seed(seed),
    );
    ensure!(
        reconstructed_challenge == invitation_record.owner_message,
        "encrypted SPAKE2 owner state does not match the invitation challenge"
    );
    let session_key = Zeroizing::new(
        owner
            .finish(&reply.requester_message)
            .map_err(|error| anyhow::anyhow!("invalid SPAKE2 requester message: {error:?}"))?,
    );
    verify_requester_confirmation(
        &session_key,
        vault_id,
        invitation,
        proposal_identity,
        &reply.requester_message,
        &invitation_record.owner_message,
        &reply.confirmation,
    )?;
    Ok((
        ProposalAuthentication {
            vault_id: *vault_id,
            invitation_id: invitation.invitation_id,
            invitation_event_hash: invitation.create_event_hash,
            response_event_hash: invitation.create_event_hash,
            signing_public_key: proposal_identity.signing_public_key,
            encryption_public_key: proposal_identity.encryption_public_key,
        },
        session_key,
    ))
}

pub fn admission_confirmation(
    session_key: &[u8],
    vault_id: &VaultId,
    parent_trust_hash: &Hash,
    epoch: &MembershipEpoch,
) -> Result<Hash> {
    let binding = admission_binding_digest(vault_id, parent_trust_hash, epoch)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(session_key)
        .map_err(|_| anyhow::anyhow!("invalid SPAKE2 session key"))?;
    mac.update(ADMISSION_CONFIRMATION_DOMAIN);
    mac.update(&binding);
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_admission_confirmation(
    session_key: &[u8],
    vault_id: &VaultId,
    parent_trust_hash: &Hash,
    epoch: &MembershipEpoch,
) -> Result<()> {
    let expected = admission_confirmation(session_key, vault_id, parent_trust_hash, epoch)?;
    ensure!(
        epoch.admission_confirmation == Some(expected),
        "membership admission confirmation does not match the SPAKE2 session"
    );
    Ok(())
}

pub fn encode_client_session_state(state: &ClientSessionState) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(SESSION_STATE_MAGIC.to_vec());
    output.extend_from_slice(&state.invitation_id);
    output.extend_from_slice(&state.invitation_event_hash);
    output.extend_from_slice(&state.final_proposal_hash);
    encode_identity(&mut output, &state.proposal_identity)?;
    put_bytes(&mut output, &state.session_key)?;
    Ok(output)
}

pub fn decode_client_session_state(bytes: &[u8]) -> Result<ClientSessionState> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == SESSION_STATE_MAGIC,
        "invalid local SPAKE2 session magic"
    );
    let state = ClientSessionState {
        invitation_id: decoder.array()?,
        invitation_event_hash: decoder.array()?,
        final_proposal_hash: decoder.array()?,
        proposal_identity: decoder.identity()?,
        session_key: Zeroizing::new(decoder.bytes(MAX_PAKE_FIELD, "SPAKE2 session key")?),
    };
    decoder.finish()?;
    Ok(state)
}

pub fn is_spake2_invitation(bytes: &[u8]) -> bool {
    bytes.starts_with(INVITATION_MAGIC)
}

fn requester_confirmation(
    session_key: &[u8],
    vault_id: &VaultId,
    invitation: &InvitationState,
    identity: &MemberIdentity,
    requester_message: &[u8],
    owner_message: &[u8],
) -> Result<Hash> {
    let mut mac = Hmac::<Sha256>::new_from_slice(session_key)
        .map_err(|_| anyhow::anyhow!("invalid SPAKE2 session key"))?;
    mac.update(REQUESTER_CONFIRMATION_DOMAIN);
    update_confirmation_binding(
        &mut mac,
        vault_id,
        invitation,
        identity,
        requester_message,
        owner_message,
    )?;
    Ok(mac.finalize().into_bytes().into())
}

fn verify_requester_confirmation(
    session_key: &[u8],
    vault_id: &VaultId,
    invitation: &InvitationState,
    identity: &MemberIdentity,
    requester_message: &[u8],
    owner_message: &[u8],
    confirmation: &Hash,
) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(session_key)
        .map_err(|_| anyhow::anyhow!("invalid SPAKE2 session key"))?;
    mac.update(REQUESTER_CONFIRMATION_DOMAIN);
    update_confirmation_binding(
        &mut mac,
        vault_id,
        invitation,
        identity,
        requester_message,
        owner_message,
    )?;
    mac.verify_slice(confirmation)
        .context("invitation phrase is wrong or requester confirmation was substituted")
}

fn update_confirmation_binding(
    mac: &mut Hmac<Sha256>,
    vault_id: &VaultId,
    invitation: &InvitationState,
    identity: &MemberIdentity,
    requester_message: &[u8],
    owner_message: &[u8],
) -> Result<()> {
    mac.update(vault_id);
    mac.update(&invitation.invitation_id);
    mac.update(&invitation.create_event_hash);
    mac.update(&invitation.create_parent_trust_hash);
    put_mac_bytes(mac, identity.name.as_bytes())?;
    mac.update(&identity.signing_public_key);
    mac.update(&identity.encryption_public_key);
    put_mac_bytes(mac, &identity.certificate)?;
    put_mac_bytes(mac, requester_message)?;
    put_mac_bytes(mac, owner_message)
}

fn spake_identities(
    vault_id: &VaultId,
    invitation_id: &[u8; 16],
    parent_trust_hash: &Hash,
) -> (Vec<u8>, Vec<u8>) {
    let common = [IDENTITY_DOMAIN, vault_id, invitation_id, parent_trust_hash].concat();
    (
        [common.as_slice(), b"/requester"].concat(),
        [common.as_slice(), b"/owner"].concat(),
    )
}

struct InvitationRecord {
    owner_message: Vec<u8>,
    state_nonce: [u8; 12],
    encrypted_owner_state: Vec<u8>,
}

fn decode_invitation(bytes: &[u8]) -> Result<InvitationRecord> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == INVITATION_MAGIC,
        "invitation uses an unsupported PAKE protocol; close it and create a new invitation"
    );
    let record = InvitationRecord {
        owner_message: decoder.bytes(SPAKE_MESSAGE_SIZE, "SPAKE2 owner challenge")?,
        state_nonce: decoder.array()?,
        encrypted_owner_state: decoder.bytes(MAX_PAKE_FIELD, "encrypted SPAKE2 owner state")?,
    };
    ensure!(
        record.owner_message.len() == SPAKE_MESSAGE_SIZE,
        "invalid SPAKE2 owner challenge size"
    );
    decoder.finish()?;
    Ok(record)
}

struct ReplyRecord {
    requester_message: Vec<u8>,
    confirmation: Hash,
}

fn decode_reply(bytes: &[u8]) -> Result<ReplyRecord> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == REPLY_MAGIC,
        "join request does not contain a SPAKE2 phrase proof"
    );
    let record = ReplyRecord {
        requester_message: decoder.bytes(SPAKE_MESSAGE_SIZE, "SPAKE2 requester message")?,
        confirmation: decoder.array()?,
    };
    ensure!(
        record.requester_message.len() == SPAKE_MESSAGE_SIZE,
        "invalid SPAKE2 requester message size"
    );
    decoder.finish()?;
    Ok(record)
}

fn decode_owner_state(bytes: &[u8]) -> Result<([u8; 32], Zeroizing<Vec<u8>>)> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == OWNER_STATE_MAGIC,
        "invalid encrypted SPAKE2 owner state"
    );
    let seed = decoder.array()?;
    let phrase = Zeroizing::new(decoder.bytes(256, "invitation phrase")?);
    decoder.finish()?;
    Ok((seed, phrase))
}

fn encode_identity(output: &mut Vec<u8>, identity: &MemberIdentity) -> Result<()> {
    put_bytes(output, identity.name.as_bytes())?;
    output.extend_from_slice(&identity.signing_public_key);
    output.extend_from_slice(&identity.encryption_public_key);
    put_bytes(output, &identity.certificate)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("SPAKE2 field is too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_mac_bytes(mac: &mut Hmac<Sha256>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("SPAKE2 binding field is too large")?;
    mac.update(&length.to_be_bytes());
    mac.update(bytes);
    Ok(())
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
            .context("SPAKE2 length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated SPAKE2 record")?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    fn bytes(&mut self, limit: usize, field: &str) -> Result<Vec<u8>> {
        let length = u32::from_be_bytes(self.array()?) as usize;
        ensure!(length <= limit, "{field} is too large");
        Ok(self.take(length)?.to_vec())
    }

    fn identity(&mut self) -> Result<MemberIdentity> {
        Ok(MemberIdentity {
            name: String::from_utf8(self.bytes(128, "member name")?)
                .context("member name is not UTF-8")?,
            signing_public_key: self.array()?,
            encryption_public_key: self.array()?,
            certificate: self.bytes(16 * 1024, "device certificate")?,
        })
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.offset == self.bytes.len(),
            "trailing SPAKE2 record data"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::{
        crypto::random_epoch_key,
        event::{EncryptedSnapshot, MembershipEpoch},
    };

    fn identity() -> MemberIdentity {
        let encryption = StaticSecret::from([44; 32]);
        MemberIdentity {
            name: "Bob".into(),
            signing_public_key: SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
            encryption_public_key: PublicKey::from(&encryption).to_bytes(),
            certificate: Vec::new(),
        }
    }

    fn invitation(pake_message: Vec<u8>) -> InvitationState {
        InvitationState {
            epoch_number: 1,
            invitation_id: [3; 16],
            expires_at: u64::MAX,
            create_event_hash: [4; 32],
            create_parent_trust_hash: [2; 32],
            pake_message,
        }
    }

    #[test]
    fn spake2_invitation_round_trip_wrong_phrase_and_admission_confirmation() {
        let vault_id = [1; 32];
        let epoch_key = random_epoch_key();
        let phrase = "abandon ability able about";
        let record =
            create_registration(&vault_id, 1, &[2; 32], &[3; 16], phrase, &epoch_key).unwrap();
        let invitation = invitation(record);
        let proposed = identity();
        let (reply, requester_key) =
            start_proposal(&vault_id, &invitation, &proposed, phrase).unwrap();
        let (_, owner_key) =
            authenticate_proposal(&vault_id, &invitation, &reply, &proposed, &epoch_key).unwrap();
        assert_eq!(&*requester_key, &*owner_key);

        let (wrong_reply, _) = start_proposal(
            &vault_id,
            &invitation,
            &proposed,
            "absorb abstract absurd abuse",
        )
        .unwrap();
        assert!(
            authenticate_proposal(&vault_id, &invitation, &wrong_reply, &proposed, &epoch_key,)
                .is_err()
        );

        let mut substituted_invitation = invitation.clone();
        substituted_invitation.create_event_hash[0] ^= 1;
        assert!(authenticate_proposal(
            &vault_id,
            &substituted_invitation,
            &reply,
            &proposed,
            &epoch_key,
        )
        .is_err());
        let mut substituted_identity = proposed.clone();
        substituted_identity.name = "Mallory".into();
        assert!(authenticate_proposal(
            &vault_id,
            &invitation,
            &reply,
            &substituted_identity,
            &epoch_key,
        )
        .is_err());

        let mut epoch = MembershipEpoch {
            epoch_number: 2,
            members: Vec::new(),
            snapshot: EncryptedSnapshot {
                nonce: [0; 12],
                ciphertext: vec![0; 16],
            },
            accepted_proposal: Some([7; 32]),
            admission_confirmation: Some([0; 32]),
        };
        epoch.admission_confirmation =
            Some(admission_confirmation(&requester_key, &vault_id, &[8; 32], &epoch).unwrap());
        verify_admission_confirmation(&owner_key, &vault_id, &[8; 32], &epoch).unwrap();
        assert!(verify_admission_confirmation(&[0; 32], &vault_id, &[8; 32], &epoch).is_err());
    }
}
