use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{decrypt_mutation, decrypt_snapshot, DecryptedMutation, EpochKey, VaultValue},
    event::{EpochMember, Event, EventPayload, Hash, MembershipEpoch, Role, VaultId},
    identity::VaultTrustRecord,
};

const GENESIS_TRUST_DOMAIN: &[u8] = b"git-vault/trust-genesis/v1";
const TRUST_DOMAIN: &[u8] = b"git-vault/trust/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkState {
    pub parent_trust_hash: Hash,
    pub candidate_event_hashes: Vec<Hash>,
}

#[derive(Clone, Debug, Default)]
pub struct DeriveOptions {
    pub hardware_checkpoint: Option<VaultTrustRecord>,
    pub local_checkpoint: Option<Hash>,
}

#[derive(Clone, Debug)]
pub struct TrustedState {
    pub vault_id: VaultId,
    pub current_trust_hash: Hash,
    pub membership_epoch: u64,
    pub members: Vec<EpochMember>,
    pub fork: Option<ForkState>,
    pub diagnostics: Vec<String>,
    pub trusted_event_hashes: Vec<Hash>,
    pub membership_event_hash: Hash,
    trusted_context_hashes: BTreeSet<Hash>,
    epoch: MembershipEpoch,
    epoch_deltas: Vec<EventPayload>,
    membership_history: BTreeMap<u64, (Hash, Hash)>,
}

impl TrustedState {
    pub fn member_for_signing_key(&self, key: &[u8; 32]) -> Option<&EpochMember> {
        self.members
            .iter()
            .find(|member| &member.identity.signing_public_key == key)
    }

    pub fn member_for_public_keys(
        &self,
        signing_key: &[u8; 32],
        encryption_key: &[u8; 32],
    ) -> Option<&EpochMember> {
        self.members.iter().find(|member| {
            &member.identity.signing_public_key == signing_key
                && &member.identity.encryption_public_key == encryption_key
        })
    }

    pub fn unlock_values(&self, epoch_key: &EpochKey) -> Result<BTreeMap<String, VaultValue>> {
        let mut values = decrypt_snapshot(
            &self.vault_id,
            self.membership_epoch,
            &self.epoch.snapshot,
            epoch_key,
        )?;
        for payload in &self.epoch_deltas {
            match payload {
                EventPayload::Mutation {
                    epoch_number,
                    nonce,
                    ciphertext,
                } => {
                    ensure!(
                        *epoch_number == self.membership_epoch,
                        "trusted Mutation event has the wrong membership epoch"
                    );
                    match decrypt_mutation(
                        &self.vault_id,
                        *epoch_number,
                        nonce,
                        ciphertext,
                        epoch_key,
                    )? {
                        DecryptedMutation::Put { key, value } => {
                            values.insert(key, value);
                        }
                        DecryptedMutation::Delete { key } => {
                            values.remove(&key);
                        }
                    }
                }
                _ => unreachable!("only value deltas are retained"),
            }
        }
        Ok(values)
    }

    pub fn trusted_checkpoint(&self, vault_name: &str) -> VaultTrustRecord {
        VaultTrustRecord {
            vault_name: vault_name.to_owned(),
            vault_id: self.vault_id,
            membership_epoch: self.membership_epoch,
            membership_event_hash: self.membership_event_hash,
            trusted_trust_hash: self
                .membership_history
                .get(&self.membership_epoch)
                .map(|(_, trust)| *trust)
                .unwrap_or(self.current_trust_hash),
        }
    }
}

pub fn derive_trusted_state(events: &[Event], options: &DeriveOptions) -> Result<TrustedState> {
    ensure!(!events.is_empty(), "vault event collection is empty");
    let mut events_by_hash = BTreeMap::new();
    let mut children = BTreeMap::<Hash, Vec<(Hash, &Event)>>::new();
    for event in events {
        event.verify_structure()?;
        let hash = event.verified_event_hash()?;
        ensure!(
            events_by_hash.insert(hash, event).is_none(),
            "duplicate event hash in verified event collection"
        );
        children
            .entry(event.parent_trust_hash)
            .or_default()
            .push((hash, event));
    }
    for candidates in children.values_mut() {
        candidates.sort_by_key(|(hash, _)| *hash);
    }
    let genesis = events.first().context("vault event collection is empty")?;
    ensure!(
        matches!(genesis.payload, EventPayload::Genesis(_)),
        "the first structurally valid event must be Genesis"
    );
    ensure!(
        genesis.parent_trust_hash == [0; 32],
        "Genesis has a nonzero parent trust hash"
    );
    let EventPayload::Genesis(epoch) = &genesis.payload else {
        unreachable!()
    };
    ensure!(
        epoch.epoch_number == 1,
        "Genesis must create membership epoch 1"
    );
    ensure!(
        epoch.members.iter().any(|member| {
            member.role == Role::Owner
                && member.identity.signing_public_key == genesis.author_signing_key
        }),
        "Genesis signer is not an initial owner"
    );
    let genesis_hash = genesis.verified_event_hash()?;
    let current_trust_hash = genesis_trust_hash(&genesis_hash);
    let mut trusted_hashes = BTreeSet::from([genesis_hash]);
    let mut membership_history = BTreeMap::from([(1, (genesis_hash, current_trust_hash))]);
    let mut state = TrustedState {
        vault_id: genesis.vault_id,
        current_trust_hash,
        membership_epoch: 1,
        members: epoch.members.clone(),
        fork: None,
        diagnostics: Vec::new(),
        trusted_event_hashes: vec![genesis_hash],
        membership_event_hash: genesis_hash,
        trusted_context_hashes: BTreeSet::from([current_trust_hash]),
        epoch: epoch.clone(),
        epoch_deltas: Vec::new(),
        membership_history: membership_history.clone(),
    };

    loop {
        let mut candidates = Vec::new();
        for (event_hash, event) in children
            .get(&state.current_trust_hash)
            .into_iter()
            .flatten()
        {
            if trusted_hashes.contains(event_hash) || event.vault_id != state.vault_id {
                continue;
            }
            if validate_transition(event, &state).is_ok() {
                candidates.push((*event_hash, *event));
            }
        }
        if candidates.is_empty() {
            break;
        }
        if candidates.len() > 1 {
            let mut hashes = candidates.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
            hashes.sort();
            state.fork = Some(ForkState {
                parent_trust_hash: state.current_trust_hash,
                candidate_event_hashes: hashes,
            });
            state
                .diagnostics
                .push("trusted replay stopped at competing authorized events".into());
            break;
        }
        let (event_hash, event) = candidates[0];
        apply_trusted_event(&mut state, event, &event_hash)?;
        state.current_trust_hash = advance_trust_hash(&state.current_trust_hash, &event_hash);
        trusted_hashes.insert(event_hash);
        state
            .trusted_context_hashes
            .insert(state.current_trust_hash);
        state.trusted_event_hashes.push(event_hash);
        if matches!(event.payload, EventPayload::MembershipEpoch(_)) {
            membership_history.insert(
                state.membership_epoch,
                (event_hash, state.current_trust_hash),
            );
            state.membership_history = membership_history.clone();
        }
    }

    classify_inert_events(&mut state, &events_by_hash, &trusted_hashes);
    validate_checkpoints(&state, options)?;
    Ok(state)
}

fn validate_transition(event: &Event, state: &TrustedState) -> Result<()> {
    let author = state
        .member_for_signing_key(&event.author_signing_key)
        .context("event author is not a current member")?;
    match &event.payload {
        EventPayload::MembershipEpoch(epoch) => {
            ensure!(
                author.role == Role::Owner,
                "membership changes require an owner"
            );
            ensure!(
                epoch.epoch_number == state.membership_epoch + 1,
                "membership epoch does not increment by one"
            );
        }
        EventPayload::Mutation { epoch_number, .. } => {
            ensure!(
                *epoch_number == state.membership_epoch,
                "value event targets a stale membership epoch"
            );
        }
        EventPayload::Genesis(_) => bail!("event type cannot extend trusted state"),
    }
    Ok(())
}

fn apply_trusted_event(state: &mut TrustedState, event: &Event, event_hash: &Hash) -> Result<()> {
    match &event.payload {
        EventPayload::MembershipEpoch(epoch) => {
            state.membership_epoch = epoch.epoch_number;
            state.members = epoch.members.clone();
            state.epoch = epoch.clone();
            state.epoch_deltas.clear();
            state.membership_event_hash = *event_hash;
        }
        EventPayload::Mutation { .. } => {
            state.epoch_deltas.push(event.payload.clone());
        }
        _ => bail!("cannot apply inert event as trusted"),
    }
    Ok(())
}

fn classify_inert_events(
    state: &mut TrustedState,
    events_by_hash: &BTreeMap<Hash, &Event>,
    trusted_hashes: &BTreeSet<Hash>,
) {
    for (hash, event) in events_by_hash {
        let hash = *hash;
        if trusted_hashes.contains(&hash) {
            continue;
        }
        match &event.payload {
            EventPayload::Genesis(_) => state
                .diagnostics
                .push("additional Genesis event is inert".into()),
            _ => state.diagnostics.push(format!(
                "event {} is structurally valid but not trusted",
                hex::encode_upper(&hash[..8])
            )),
        }
    }
}

fn validate_checkpoints(state: &TrustedState, options: &DeriveOptions) -> Result<()> {
    if let Some(checkpoint) = &options.hardware_checkpoint {
        ensure!(
            checkpoint.vault_id == state.vault_id,
            "hardware checkpoint is for another vault"
        );
        ensure!(
            state.membership_epoch >= checkpoint.membership_epoch,
            "repository membership rollback detected by hardware checkpoint"
        );
        let Some((event_hash, trust_hash)) =
            state.membership_history.get(&checkpoint.membership_epoch)
        else {
            bail!("hardware checkpoint membership state is absent from this log");
        };
        ensure!(
            event_hash == &checkpoint.membership_event_hash
                && trust_hash == &checkpoint.trusted_trust_hash,
            "repository membership fork conflicts with hardware checkpoint"
        );
    }
    if let Some(local) = options.local_checkpoint {
        ensure!(
            local == state.current_trust_hash || state.trusted_context_hashes.contains(&local),
            "ordinary vault rollback detected by local freshness checkpoint"
        );
    }
    Ok(())
}

fn genesis_trust_hash(event_hash: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_TRUST_DOMAIN);
    hasher.update(event_hash);
    hasher.finalize().into()
}

pub fn advance_trust_hash(parent: &Hash, event_hash: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(TRUST_DOMAIN);
    hasher.update(parent);
    hasher.update(event_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::{
        crypto::{encrypt_snapshot, random_epoch_key, wrap_epoch_key},
        event::{EventPayload, MemberIdentity},
        identity::{DeviceIdentity, IdentityBackend, IdentitySession},
    };

    struct TestIdentity {
        device: DeviceIdentity,
        signing: SigningKey,
        encryption: StaticSecret,
    }

    impl IdentitySession for TestIdentity {
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

    fn identity(seed: u8, name: &str) -> TestIdentity {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let encryption = StaticSecret::from([seed.wrapping_add(64); 32]);
        let device = DeviceIdentity {
            backend: IdentityBackend::TouchId,
            locator: name.into(),
            display_name: name.into(),
            encryption_public_key: PublicKey::from(&encryption).to_bytes(),
            signing_public_key: signing.verifying_key().to_bytes(),
        };
        TestIdentity {
            device,
            signing,
            encryption,
        }
    }

    fn member(identity: &TestIdentity, role: Role, key: &[u8; 32], epoch: u64) -> EpochMember {
        let public = MemberIdentity {
            name: identity.device.display_name.clone(),
            signing_public_key: identity.device.signing_public_key,
            encryption_public_key: identity.device.encryption_public_key,
        };
        EpochMember {
            wrapped_epoch_key: wrap_epoch_key(&[1; 32], epoch, &public, key).unwrap(),
            identity: public,
            role,
        }
    }

    fn epoch(number: u64, identities: &[(&TestIdentity, Role)], key: &[u8; 32]) -> MembershipEpoch {
        MembershipEpoch {
            epoch_number: number,
            members: identities
                .iter()
                .map(|(identity, role)| member(identity, *role, key, number))
                .collect(),
            snapshot: encrypt_snapshot(&[1; 32], number, &BTreeMap::new(), key).unwrap(),
        }
    }

    fn sign_event(identity: &mut TestIdentity, parent: Hash, payload: EventPayload) -> Event {
        Event::unsigned([1; 32], parent, identity.device.signing_public_key, payload)
            .sign(identity)
            .unwrap()
    }

    fn genesis(owner: &mut TestIdentity, epoch_key: &[u8; 32]) -> Event {
        let payload = EventPayload::Genesis(epoch(1, &[(owner, Role::Owner)], epoch_key));
        sign_event(owner, [0; 32], payload)
    }

    fn trust_after(event: &Event) -> Hash {
        genesis_trust_hash(&event.event_hash().unwrap())
    }

    fn mutation(epoch_number: u64, marker: u8) -> EventPayload {
        EventPayload::Mutation {
            epoch_number,
            nonce: [marker; 12],
            ciphertext: vec![marker; 16],
        }
    }

    #[test]
    fn authorized_event_is_trusted_and_unauthorized_event_is_inert() {
        let mut alice = identity(1, "Alice");
        let mut mallory = identity(2, "Mallory");
        let key = random_epoch_key();
        let genesis = genesis(&mut alice, &key);
        let parent = trust_after(&genesis);
        let authorized = sign_event(&mut alice, parent, mutation(1, 1));
        let unauthorized = sign_event(&mut mallory, parent, mutation(1, 2));
        let state = derive_trusted_state(
            &[genesis, unauthorized, authorized.clone()],
            &DeriveOptions::default(),
        )
        .unwrap();
        assert_eq!(state.trusted_event_hashes.len(), 2);
        assert_eq!(
            state.trusted_event_hashes[1],
            authorized.event_hash().unwrap()
        );
        assert!(state.fork.is_none());
    }

    #[test]
    fn non_owner_member_can_append_secret_changes() {
        let mut alice = identity(21, "Alice");
        let mut bob = identity(22, "Bob");
        let key = random_epoch_key();
        let first_epoch = epoch(1, &[(&alice, Role::Owner), (&bob, Role::Member)], &key);
        let genesis = sign_event(&mut alice, [0; 32], EventPayload::Genesis(first_epoch));
        let parent = trust_after(&genesis);
        let edit = sign_event(&mut bob, parent, mutation(1, 3));
        let state =
            derive_trusted_state(&[genesis, edit.clone()], &DeriveOptions::default()).unwrap();
        assert_eq!(state.trusted_event_hashes.len(), 2);
        assert_eq!(state.trusted_event_hashes[1], edit.event_hash().unwrap());
    }

    #[test]
    fn replay_follows_parent_hashes_when_physical_records_are_out_of_order() {
        let mut alice = identity(13, "Alice");
        let key = random_epoch_key();
        let genesis = genesis(&mut alice, &key);
        let h1 = trust_after(&genesis);
        let first = sign_event(&mut alice, h1, mutation(1, 4));
        let h2 = advance_trust_hash(&h1, &first.event_hash().unwrap());
        let second = sign_event(&mut alice, h2, mutation(1, 5));
        let state = derive_trusted_state(
            &[genesis, second.clone(), first.clone()],
            &DeriveOptions::default(),
        )
        .unwrap();
        assert_eq!(state.trusted_event_hashes.len(), 3);
        assert_eq!(state.trusted_event_hashes[1], first.event_hash().unwrap());
        assert_eq!(state.trusted_event_hashes[2], second.event_hash().unwrap());
    }

    #[test]
    fn competing_authorized_children_stop_as_a_fork() {
        let mut alice = identity(3, "Alice");
        let key = random_epoch_key();
        let genesis = genesis(&mut alice, &key);
        let parent = trust_after(&genesis);
        let first = sign_event(&mut alice, parent, mutation(1, 6));
        let second = sign_event(&mut alice, parent, mutation(1, 7));
        let state =
            derive_trusted_state(&[genesis, first, second], &DeriveOptions::default()).unwrap();
        assert!(state.fork.is_some());
        assert_eq!(state.trusted_event_hashes.len(), 1);
    }

    #[test]
    fn wrong_parent_and_removed_owner_events_are_ignored() {
        let mut alice = identity(4, "Alice");
        let mut bob = identity(5, "Bob");
        let key1 = random_epoch_key();
        let mut first_epoch = epoch(1, &[(&alice, Role::Owner), (&bob, Role::Owner)], &key1);
        first_epoch.epoch_number = 1;
        let genesis = sign_event(&mut alice, [0; 32], EventPayload::Genesis(first_epoch));
        let h1 = trust_after(&genesis);
        let key2 = random_epoch_key();
        let second_epoch = epoch(2, &[(&alice, Role::Owner)], &key2);
        let remove = sign_event(&mut alice, h1, EventPayload::MembershipEpoch(second_epoch));
        let h2 = advance_trust_hash(&h1, &remove.event_hash().unwrap());
        let stale = sign_event(&mut bob, h2, mutation(2, 8));
        let wrong_parent = sign_event(&mut alice, [9; 32], mutation(2, 9));
        let state = derive_trusted_state(
            &[genesis, remove, stale, wrong_parent],
            &DeriveOptions::default(),
        )
        .unwrap();
        assert_eq!(state.members.len(), 1);
        assert_eq!(state.trusted_event_hashes.len(), 2);
    }

    #[test]
    fn owner_can_add_a_member_in_one_epoch() {
        let mut alice = identity(6, "Alice");
        let mut bob = identity(7, "Bob");
        let key1 = random_epoch_key();
        let genesis = genesis(&mut alice, &key1);
        let h1 = trust_after(&genesis);
        let key2 = random_epoch_key();
        let second_epoch = epoch(2, &[(&alice, Role::Owner), (&bob, Role::Owner)], &key2);
        let admit = sign_event(&mut alice, h1, EventPayload::MembershipEpoch(second_epoch));
        let h2 = advance_trust_hash(&h1, &admit.event_hash().unwrap());
        let bob_event = sign_event(&mut bob, h2, mutation(2, 11));
        let state =
            derive_trusted_state(&[genesis, admit, bob_event], &DeriveOptions::default()).unwrap();
        assert_eq!(state.trusted_event_hashes.len(), 3);
        assert_eq!(state.membership_epoch, 2);
        assert_eq!(state.members.len(), 2);
    }

    #[test]
    fn membership_change_rotates_key() {
        let mut alice = identity(10, "Alice");
        let bob = identity(11, "Bob");
        let key1 = random_epoch_key();
        let first_epoch = epoch(1, &[(&alice, Role::Owner), (&bob, Role::Member)], &key1);
        let bob_old_wrap = first_epoch.members[1].wrapped_epoch_key.clone();
        let genesis = sign_event(&mut alice, [0; 32], EventPayload::Genesis(first_epoch));
        let h1 = trust_after(&genesis);
        let key2 = random_epoch_key();
        assert_ne!(&*key1, &*key2);
        let second_epoch = epoch(2, &[(&alice, Role::Owner)], &key2);
        let remove = sign_event(&mut alice, h1, EventPayload::MembershipEpoch(second_epoch));
        let state = derive_trusted_state(&[genesis, remove], &DeriveOptions::default()).unwrap();
        assert_eq!(state.membership_epoch, 2);
        assert_eq!(state.members.len(), 1);
        assert!(state
            .members
            .iter()
            .all(|member| member.identity.name != "Bob"));

        let mut bob = bob;
        let bob_member = MemberIdentity {
            name: "Bob".into(),
            signing_public_key: bob.device.signing_public_key,
            encryption_public_key: bob.device.encryption_public_key,
        };
        let historical =
            crate::crypto::unwrap_epoch_key(&[1; 32], 1, &bob_member, &bob_old_wrap, &mut bob)
                .unwrap();
        assert_eq!(&*historical, &*key1);
    }

    #[test]
    fn local_and_hardware_checkpoints_detect_rollback() {
        let mut alice = identity(9, "Alice");
        let key = random_epoch_key();
        let genesis = genesis(&mut alice, &key);
        let state = derive_trusted_state(&[genesis.clone()], &DeriveOptions::default()).unwrap();
        let checkpoint = state.trusted_checkpoint("test");
        let replacement = Event::unsigned(
            [2; 32],
            [0; 32],
            alice.device.signing_public_key,
            EventPayload::Genesis(epoch(1, &[(&alice, Role::Owner)], &key)),
        )
        .sign(&mut alice)
        .unwrap();
        assert!(derive_trusted_state(
            &[replacement],
            &DeriveOptions {
                hardware_checkpoint: Some(checkpoint.clone()),
                ..DeriveOptions::default()
            }
        )
        .is_err());

        let mut hardware = checkpoint;
        hardware.membership_epoch = 2;
        assert!(derive_trusted_state(
            &[genesis.clone()],
            &DeriveOptions {
                hardware_checkpoint: Some(hardware),
                ..DeriveOptions::default()
            }
        )
        .is_err());
        assert!(derive_trusted_state(
            &[genesis],
            &DeriveOptions {
                local_checkpoint: Some([0x55; 32]),
                ..DeriveOptions::default()
            }
        )
        .is_err());
    }
}
