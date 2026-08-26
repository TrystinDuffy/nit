use anyhow::{ensure, Context, Result};
use argon2::Argon2;
use bip39::Language;
use hmac::{Hmac, Mac};
use opaque_ke::{
    ciphersuite::CipherSuite, key_exchange::tripledh::TripleDh, ClientLogin,
    ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{decrypt_protocol_state, encrypt_protocol_state, EpochKey, ProtocolStateContext},
    event::{admission_binding_digest, Hash, MemberIdentity, MembershipEpoch, VaultId},
    state::{InvitationResponseState, InvitationState, ProposalAuthentication},
};

const REGISTRATION_MAGIC: &[u8; 8] = b"GVOPQRG1";
const RESPONSE_MAGIC: &[u8; 8] = b"GVOPQRS1";
const CLIENT_STATE_MAGIC: &[u8; 8] = b"GVOPQCL1";
const SESSION_STATE_MAGIC: &[u8; 8] = b"GVOPQSK1";
const SETUP_PURPOSE: &[u8] = b"opaque-server-setup";
const RESPONSE_PURPOSE: &[u8] = b"opaque-server-login";
const CONTEXT_DOMAIN: &[u8] = b"git-vault/opaque-context/v1";
const CREDENTIAL_DOMAIN: &[u8] = b"git-vault/opaque-credential/v1";
const ADMISSION_CONFIRMATION_DOMAIN: &[u8] = b"git-vault/admission-confirmation/v1";
const MAX_OPAQUE_FIELD: usize = 64 * 1024;

pub struct VaultCipherSuite;

impl CipherSuite for VaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Argon2<'static>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientStartState {
    pub invitation_id: [u8; 16],
    pub invitation_event_hash: Hash,
    pub proposal_identity: MemberIdentity,
    pub opaque_state: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientSessionState {
    pub invitation_id: [u8; 16],
    pub invitation_event_hash: Hash,
    pub response_event_hash: Hash,
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

pub fn create_registration(
    vault_id: &VaultId,
    epoch_number: u64,
    parent_trust_hash: &Hash,
    invitation_id: &[u8; 16],
    phrase: &str,
    epoch_key: &EpochKey,
) -> Result<Vec<u8>> {
    validate_phrase(phrase)?;
    let mut rng = OsRng;
    let setup = ServerSetup::<VaultCipherSuite>::new(&mut rng);
    let client = ClientRegistration::<VaultCipherSuite>::start(&mut rng, phrase.as_bytes())
        .context("cannot start OPAQUE invitation registration")?;
    let server = ServerRegistration::<VaultCipherSuite>::start(
        &setup,
        RegistrationRequest::deserialize(&client.message.serialize())
            .context("cannot decode OPAQUE registration request")?,
        &credential_identifier(vault_id, invitation_id),
    )
    .context("cannot create OPAQUE registration response")?;
    let finished = client
        .state
        .finish(
            &mut rng,
            phrase.as_bytes(),
            server.message,
            ClientRegistrationFinishParameters::default(),
        )
        .context("cannot finish OPAQUE invitation registration")?;
    let password_file = ServerRegistration::finish(finished.message).serialize();
    let mut setup_bytes = Zeroizing::new(setup.serialize().to_vec());
    let (nonce, encrypted_setup) = encrypt_protocol_state(
        &ProtocolStateContext {
            vault_id,
            epoch_number,
            invitation_id,
            reference_hash: parent_trust_hash,
            purpose: SETUP_PURPOSE,
        },
        &setup_bytes,
        epoch_key,
    )?;
    setup_bytes.zeroize();

    let mut output = REGISTRATION_MAGIC.to_vec();
    put_bytes(&mut output, &password_file)?;
    output.extend_from_slice(&nonce);
    put_bytes(&mut output, &encrypted_setup)?;
    ensure!(
        output.len() <= MAX_OPAQUE_FIELD,
        "OPAQUE invitation record is too large"
    );
    Ok(output)
}

pub fn start_proposal(
    invitation: &InvitationState,
    identity: MemberIdentity,
    phrase: &str,
) -> Result<(ClientStartState, Vec<u8>)> {
    validate_phrase(phrase)?;
    decode_registration(&invitation.pake_message)?;
    let mut rng = OsRng;
    let started = ClientLogin::<VaultCipherSuite>::start(&mut rng, phrase.as_bytes())
        .context("cannot start OPAQUE invitation login")?;
    Ok((
        ClientStartState {
            invitation_id: invitation.invitation_id,
            invitation_event_hash: invitation.create_event_hash,
            proposal_identity: identity,
            opaque_state: started.state.serialize().to_vec(),
        },
        started.message.serialize().to_vec(),
    ))
}

pub fn create_server_response(
    vault_id: &VaultId,
    invitation: &InvitationState,
    proposal_event_hash: &Hash,
    proposal_identity: &MemberIdentity,
    credential_request: &[u8],
    epoch_key: &EpochKey,
) -> Result<Vec<u8>> {
    let registration = decode_registration(&invitation.pake_message)?;
    let setup_bytes = decrypt_protocol_state(
        &ProtocolStateContext {
            vault_id,
            epoch_number: invitation.epoch_number,
            invitation_id: &invitation.invitation_id,
            reference_hash: &invitation.create_parent_trust_hash,
            purpose: SETUP_PURPOSE,
        },
        &registration.setup_nonce,
        &registration.encrypted_setup,
        epoch_key,
    )?;
    let setup = ServerSetup::<VaultCipherSuite>::deserialize(&setup_bytes)
        .context("cannot decode encrypted OPAQUE server setup")?;
    let password_file =
        ServerRegistration::<VaultCipherSuite>::deserialize(&registration.password_file)
            .context("cannot decode OPAQUE invitation password file")?;
    let request = CredentialRequest::<VaultCipherSuite>::deserialize(credential_request)
        .context("cannot decode OPAQUE credential request")?;
    let context = opaque_context(vault_id, invitation, proposal_event_hash, proposal_identity);
    let mut rng = OsRng;
    let response = ServerLogin::start(
        &mut rng,
        &setup,
        Some(password_file),
        request,
        &credential_identifier(vault_id, &invitation.invitation_id),
        ServerLoginStartParameters {
            context: Some(&context),
            ..ServerLoginStartParameters::default()
        },
    )
    .context("cannot create OPAQUE invitation response")?;
    let mut server_state = Zeroizing::new(response.state.serialize().to_vec());
    let (nonce, encrypted_state) = encrypt_protocol_state(
        &ProtocolStateContext {
            vault_id,
            epoch_number: invitation.epoch_number,
            invitation_id: &invitation.invitation_id,
            reference_hash: proposal_event_hash,
            purpose: RESPONSE_PURPOSE,
        },
        &server_state,
        epoch_key,
    )?;
    server_state.zeroize();

    let mut output = RESPONSE_MAGIC.to_vec();
    put_bytes(&mut output, &response.message.serialize())?;
    output.extend_from_slice(&nonce);
    put_bytes(&mut output, &encrypted_state)?;
    ensure!(
        output.len() <= MAX_OPAQUE_FIELD,
        "OPAQUE response record is too large"
    );
    Ok(output)
}

pub fn finish_proposal(
    vault_id: &VaultId,
    invitation: &InvitationState,
    proposal_event_hash: &Hash,
    response: &InvitationResponseState,
    state: ClientStartState,
    phrase: &str,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    validate_phrase(phrase)?;
    ensure!(
        state.invitation_id == invitation.invitation_id
            && state.invitation_event_hash == invitation.create_event_hash
            && response.proposal_event_hash == *proposal_event_hash,
        "local OPAQUE state does not match the invitation response"
    );
    let response_record = decode_response(&response.pake_message)?;
    let client = ClientLogin::<VaultCipherSuite>::deserialize(&state.opaque_state)
        .context("cannot decode local OPAQUE client state")?;
    let credential_response =
        CredentialResponse::<VaultCipherSuite>::deserialize(&response_record.credential_response)
            .context("cannot decode OPAQUE credential response")?;
    let context = opaque_context(
        vault_id,
        invitation,
        proposal_event_hash,
        &state.proposal_identity,
    );
    let finished = client
        .finish(
            phrase.as_bytes(),
            credential_response,
            ClientLoginFinishParameters::new(Some(&context), Default::default(), None),
        )
        .context("invitation phrase is incorrect or the OPAQUE response is invalid")?;
    Ok((
        finished.message.serialize().to_vec(),
        Zeroizing::new(finished.session_key.to_vec()),
    ))
}

pub fn authenticate_final_proposal(
    vault_id: &VaultId,
    invitation: &InvitationState,
    response: &InvitationResponseState,
    finalization: &[u8],
    proposal_identity: &MemberIdentity,
    epoch_key: &EpochKey,
) -> Result<(ProposalAuthentication, Zeroizing<Vec<u8>>)> {
    let response_record = decode_response(&response.pake_message)?;
    let server_state = decrypt_protocol_state(
        &ProtocolStateContext {
            vault_id,
            epoch_number: response.epoch_number,
            invitation_id: &response.invitation_id,
            reference_hash: &response.proposal_event_hash,
            purpose: RESPONSE_PURPOSE,
        },
        &response_record.state_nonce,
        &response_record.encrypted_server_state,
        epoch_key,
    )?;
    let server = ServerLogin::<VaultCipherSuite>::deserialize(&server_state)
        .context("cannot decode encrypted OPAQUE server login state")?;
    let finalization = CredentialFinalization::<VaultCipherSuite>::deserialize(finalization)
        .context("cannot decode OPAQUE credential finalization")?;
    let finished = server
        .finish(finalization)
        .context("OPAQUE requester key confirmation failed")?;
    Ok((
        ProposalAuthentication {
            vault_id: *vault_id,
            invitation_id: invitation.invitation_id,
            invitation_event_hash: invitation.create_event_hash,
            response_event_hash: response.event_hash,
            signing_public_key: proposal_identity.signing_public_key,
            encryption_public_key: proposal_identity.encryption_public_key,
        },
        Zeroizing::new(finished.session_key.to_vec()),
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
        .map_err(|_| anyhow::anyhow!("invalid OPAQUE session key"))?;
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
        "membership admission confirmation does not match the OPAQUE session"
    );
    Ok(())
}

pub fn encode_client_start_state(state: &ClientStartState) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(CLIENT_STATE_MAGIC.to_vec());
    output.extend_from_slice(&state.invitation_id);
    output.extend_from_slice(&state.invitation_event_hash);
    encode_identity(&mut output, &state.proposal_identity)?;
    put_bytes(&mut output, &state.opaque_state)?;
    Ok(output)
}

pub fn decode_client_start_state(bytes: &[u8]) -> Result<ClientStartState> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == CLIENT_STATE_MAGIC,
        "invalid local OPAQUE state magic"
    );
    let state = ClientStartState {
        invitation_id: decoder.array()?,
        invitation_event_hash: decoder.array()?,
        proposal_identity: decoder.identity()?,
        opaque_state: decoder.bytes(MAX_OPAQUE_FIELD, "OPAQUE client state")?,
    };
    decoder.finish()?;
    Ok(state)
}

pub fn encode_client_session_state(state: &ClientSessionState) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(SESSION_STATE_MAGIC.to_vec());
    output.extend_from_slice(&state.invitation_id);
    output.extend_from_slice(&state.invitation_event_hash);
    output.extend_from_slice(&state.response_event_hash);
    output.extend_from_slice(&state.final_proposal_hash);
    encode_identity(&mut output, &state.proposal_identity)?;
    put_bytes(&mut output, &state.session_key)?;
    Ok(output)
}

pub fn decode_client_session_state(bytes: &[u8]) -> Result<ClientSessionState> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == SESSION_STATE_MAGIC,
        "invalid local OPAQUE session magic"
    );
    let state = ClientSessionState {
        invitation_id: decoder.array()?,
        invitation_event_hash: decoder.array()?,
        response_event_hash: decoder.array()?,
        final_proposal_hash: decoder.array()?,
        proposal_identity: decoder.identity()?,
        session_key: Zeroizing::new(decoder.bytes(MAX_OPAQUE_FIELD, "OPAQUE session key")?),
    };
    decoder.finish()?;
    Ok(state)
}

fn credential_identifier(vault_id: &VaultId, invitation_id: &[u8; 16]) -> Vec<u8> {
    [CREDENTIAL_DOMAIN, vault_id, invitation_id].concat()
}

fn opaque_context(
    vault_id: &VaultId,
    invitation: &InvitationState,
    proposal_event_hash: &Hash,
    identity: &MemberIdentity,
) -> Vec<u8> {
    [
        CONTEXT_DOMAIN,
        vault_id,
        &invitation.invitation_id,
        &invitation.create_event_hash,
        proposal_event_hash,
        &identity.signing_public_key,
        &identity.encryption_public_key,
    ]
    .concat()
}

struct RegistrationRecord {
    password_file: Vec<u8>,
    setup_nonce: [u8; 12],
    encrypted_setup: Vec<u8>,
}

fn decode_registration(bytes: &[u8]) -> Result<RegistrationRecord> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == REGISTRATION_MAGIC,
        "invalid OPAQUE invitation magic"
    );
    let record = RegistrationRecord {
        password_file: decoder.bytes(MAX_OPAQUE_FIELD, "OPAQUE password file")?,
        setup_nonce: decoder.array()?,
        encrypted_setup: decoder.bytes(MAX_OPAQUE_FIELD, "encrypted OPAQUE setup")?,
    };
    decoder.finish()?;
    Ok(record)
}

struct ResponseRecord {
    credential_response: Vec<u8>,
    state_nonce: [u8; 12],
    encrypted_server_state: Vec<u8>,
}

fn decode_response(bytes: &[u8]) -> Result<ResponseRecord> {
    let mut decoder = Decoder::new(bytes);
    ensure!(
        decoder.take(8)? == RESPONSE_MAGIC,
        "invalid OPAQUE response magic"
    );
    let record = ResponseRecord {
        credential_response: decoder.bytes(MAX_OPAQUE_FIELD, "OPAQUE credential response")?,
        state_nonce: decoder.array()?,
        encrypted_server_state: decoder.bytes(MAX_OPAQUE_FIELD, "encrypted OPAQUE state")?,
    };
    decoder.finish()?;
    Ok(record)
}

fn encode_identity(output: &mut Vec<u8>, identity: &MemberIdentity) -> Result<()> {
    put_bytes(output, identity.name.as_bytes())?;
    output.extend_from_slice(&identity.signing_public_key);
    output.extend_from_slice(&identity.encryption_public_key);
    put_bytes(output, &identity.certificate)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("OPAQUE field is too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
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
            .context("OPAQUE length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated OPAQUE record")?;
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
            "trailing OPAQUE record data"
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
        state::InvitationResponseState,
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

    #[test]
    fn opaque_invitation_round_trip_and_wrong_phrase_failure() {
        let vault_id = [1; 32];
        let parent = [2; 32];
        let invitation_id = [3; 16];
        let invitation_hash = [4; 32];
        let proposal_hash = [5; 32];
        let response_hash = [6; 32];
        let epoch_key = random_epoch_key();
        let phrase = "abandon ability able about";
        let registration =
            create_registration(&vault_id, 1, &parent, &invitation_id, phrase, &epoch_key).unwrap();
        let invitation = InvitationState {
            epoch_number: 1,
            invitation_id,
            expires_at: u64::MAX,
            create_event_hash: invitation_hash,
            create_parent_trust_hash: parent,
            pake_message: registration,
        };
        let proposed = identity();
        let (client_state, request) =
            start_proposal(&invitation, proposed.clone(), phrase).unwrap();
        let response_message = create_server_response(
            &vault_id,
            &invitation,
            &proposal_hash,
            &proposed,
            &request,
            &epoch_key,
        )
        .unwrap();
        let response = InvitationResponseState {
            event_hash: response_hash,
            epoch_number: 1,
            invitation_id,
            proposal_event_hash: proposal_hash,
            pake_message: response_message,
        };
        let (finalization, client_key) = finish_proposal(
            &vault_id,
            &invitation,
            &proposal_hash,
            &response,
            client_state,
            phrase,
        )
        .unwrap();
        let (authentication, server_key) = authenticate_final_proposal(
            &vault_id,
            &invitation,
            &response,
            &finalization,
            &proposed,
            &epoch_key,
        )
        .unwrap();
        assert_eq!(&*client_key, &*server_key);
        assert_eq!(authentication.response_event_hash, response_hash);

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
            Some(admission_confirmation(&client_key, &vault_id, &[8; 32], &epoch).unwrap());
        verify_admission_confirmation(&server_key, &vault_id, &[8; 32], &epoch).unwrap();
        assert!(verify_admission_confirmation(&[0; 64], &vault_id, &[8; 32], &epoch).is_err());

        let (wrong_state, _) = start_proposal(
            &invitation,
            proposed.clone(),
            "absorb abstract absurd abuse",
        )
        .unwrap();
        assert!(finish_proposal(
            &vault_id,
            &invitation,
            &proposal_hash,
            &response,
            wrong_state,
            "absorb abstract absurd abuse",
        )
        .is_err());

        let second_proposal_hash = [9; 32];
        let (second_state, second_request) =
            start_proposal(&invitation, proposed.clone(), phrase).unwrap();
        let second_response_message = create_server_response(
            &vault_id,
            &invitation,
            &second_proposal_hash,
            &proposed,
            &second_request,
            &epoch_key,
        )
        .unwrap();
        let second_response = InvitationResponseState {
            event_hash: [10; 32],
            epoch_number: 1,
            invitation_id,
            proposal_event_hash: second_proposal_hash,
            pake_message: second_response_message,
        };
        let mut substituted_invitation = invitation.clone();
        substituted_invitation.create_event_hash[0] ^= 1;
        assert!(finish_proposal(
            &vault_id,
            &substituted_invitation,
            &second_proposal_hash,
            &second_response,
            second_state,
            phrase,
        )
        .is_err());
    }
}
