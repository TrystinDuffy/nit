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
    /// Event hashes previously accepted by this repository. Every one must remain trusted.
    pub local_checkpoint: Option<Vec<Hash>>,
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
    /// Canonically sorted heads of the current epoch's mutation DAG.
    pub mutation_heads: Vec<Hash>,
    epoch: MembershipEpoch,
    epoch_deltas: Vec<(Hash, EventPayload)>,
    mutation_parents: BTreeMap<Hash, Vec<Hash>>,
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
        let mut last_change = BTreeMap::<String, Hash>::new();
        let mut conflicts = BTreeSet::new();
        for (event_hash, payload) in &self.epoch_deltas {
            match payload {
                EventPayload::Mutation {
                    epoch_number,
                    nonce,
                    ciphertext,
                    ..
                } => {
                    ensure!(
                        *epoch_number == self.membership_epoch,
                        "trusted Mutation event has the wrong membership epoch"
                    );
                    let mutation = decrypt_mutation(
                        &self.vault_id,
                        *epoch_number,
                        nonce,
                        ciphertext,
                        epoch_key,
                    )?;
                    let key = match &mutation {
                        DecryptedMutation::Put { key, .. } | DecryptedMutation::Delete { key } => {
                            key
                        }
                    };
                    if let Some(previous) = last_change.get(key) {
                        if !is_ancestor(*previous, *event_hash, &self.mutation_parents) {
                            conflicts.insert(key.clone());
                        }
                    }
                    match mutation {
                        DecryptedMutation::Put { key, value } => {
                            last_change.insert(key.clone(), *event_hash);
                            values.insert(key, value);
                        }
                        DecryptedMutation::Delete { key } => {
                            last_change.insert(key.clone(), *event_hash);
                            values.remove(&key);
                        }
                    }
                }
                _ => unreachable!("only value deltas are retained"),
            }
        }
        if !conflicts.is_empty() {
            eprintln!(
                "WARNING: concurrent changes affected {}; deterministic DAG order selected the displayed values",
                conflicts.into_iter().collect::<Vec<_>>().join(", ")
            );
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
    let mut control_children = BTreeMap::<Hash, Vec<(Hash, &Event)>>::new();
    for event in events {
        event.verify_structure()?;
        let hash = event.verified_event_hash()?;
        ensure!(
            events_by_hash.insert(hash, event).is_none(),
            "duplicate event hash in verified event collection"
        );
        if matches!(event.payload, EventPayload::MembershipEpoch(_)) {
            control_children
                .entry(event.parent_trust_hash)
                .or_default()
                .push((hash, event));
        }
    }
    for candidates in control_children.values_mut() {
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
        epoch.previous_epoch_heads.is_empty(),
        "Genesis has preceding mutation heads"
    );
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
        mutation_heads: Vec::new(),
        epoch: epoch.clone(),
        epoch_deltas: Vec::new(),
        mutation_parents: BTreeMap::new(),
        membership_history: membership_history.clone(),
    };

    loop {
        let mut candidates = Vec::new();
        for (event_hash, event) in control_children
            .get(&state.current_trust_hash)
            .into_iter()
            .flatten()
        {
            if event.vault_id != state.vault_id {
                continue;
            }
            let EventPayload::MembershipEpoch(next_epoch) = &event.payload else {
                unreachable!()
            };
            if validate_membership_transition(event, next_epoch, &state).is_err() {
                continue;
            }
            if mutation_closure(&next_epoch.previous_epoch_heads, &events_by_hash, &state).is_err()
            {
                continue;
            }
            candidates.push((*event_hash, *event));
        }
        if candidates.is_empty() {
            break;
        }
        if candidates.len() > 1 {
            state.fork = Some(ForkState {
                parent_trust_hash: state.current_trust_hash,
                candidate_event_hashes: candidates.iter().map(|(hash, _)| *hash).collect(),
            });
            state
                .diagnostics
                .push("membership replay stopped at competing authorized epochs".into());
            break;
        }

        let (event_hash, event) = candidates[0];
        let EventPayload::MembershipEpoch(next_epoch) = &event.payload else {
            unreachable!()
        };
        let closed_mutations =
            mutation_closure(&next_epoch.previous_epoch_heads, &events_by_hash, &state)?;
        for hash in closed_mutations {
            if trusted_hashes.insert(hash) {
                state.trusted_event_hashes.push(hash);
            }
        }

        state.current_trust_hash = advance_trust_hash(&state.current_trust_hash, &event_hash);
        trusted_hashes.insert(event_hash);
        state.trusted_event_hashes.push(event_hash);
        state.membership_epoch = next_epoch.epoch_number;
        state.members = next_epoch.members.clone();
        state.epoch = next_epoch.clone();
        state.epoch_deltas.clear();
        state.mutation_parents.clear();
        state.mutation_heads.clear();
        state.membership_event_hash = event_hash;
        membership_history.insert(
            state.membership_epoch,
            (event_hash, state.current_trust_hash),
        );
        state.membership_history = membership_history.clone();
    }

    if state.fork.is_none() {
        let current_mutations = current_epoch_mutations(&events_by_hash, &state)?;
        let mut parents_used = BTreeSet::new();
        for hash in &current_mutations {
            let event = events_by_hash[hash];
            let EventPayload::Mutation { parents, .. } = &event.payload else {
                unreachable!()
            };
            parents_used.extend(parents.iter().copied());
            state.mutation_parents.insert(*hash, parents.clone());
            state.epoch_deltas.push((*hash, event.payload.clone()));
            if trusted_hashes.insert(*hash) {
                state.trusted_event_hashes.push(*hash);
            }
        }
        state.mutation_heads = current_mutations
            .iter()
            .filter(|hash| !parents_used.contains(*hash))
            .copied()
            .collect();
        state.mutation_heads.sort();
    }

    classify_inert_events(&mut state, &events_by_hash, &trusted_hashes);
    validate_checkpoints(&state, options)?;
    Ok(state)
}

fn validate_membership_transition(
    event: &Event,
    epoch: &MembershipEpoch,
    state: &TrustedState,
) -> Result<()> {
    let author = state
        .member_for_signing_key(&event.author_signing_key)
        .context("membership author is not a current member")?;
    ensure!(
        author.role == Role::Owner,
        "membership changes require an owner"
    );
    ensure!(
        epoch.epoch_number == state.membership_epoch + 1,
        "membership epoch does not increment by one"
    );
    Ok(())
}

fn validate_mutation(event: &Event, state: &TrustedState) -> Result<()> {
    ensure!(
        event.vault_id == state.vault_id,
        "mutation is for another vault"
    );
    ensure!(
        event.parent_trust_hash == state.current_trust_hash,
        "mutation targets another membership context"
    );
    ensure!(
        state
            .member_for_signing_key(&event.author_signing_key)
            .is_some(),
        "mutation author is not a member of its epoch"
    );
    let EventPayload::Mutation { epoch_number, .. } = &event.payload else {
        bail!("event is not a mutation")
    };
    ensure!(
        *epoch_number == state.membership_epoch,
        "mutation targets another membership epoch"
    );
    Ok(())
}

fn mutation_closure(
    heads: &[Hash],
    events: &BTreeMap<Hash, &Event>,
    state: &TrustedState,
) -> Result<Vec<Hash>> {
    let mut selected = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for head in heads {
        visit_mutation(*head, events, state, &mut visiting, &mut selected)?;
    }
    topological_mutations(&selected, events)
}

fn visit_mutation(
    hash: Hash,
    events: &BTreeMap<Hash, &Event>,
    state: &TrustedState,
    visiting: &mut BTreeSet<Hash>,
    selected: &mut BTreeSet<Hash>,
) -> Result<()> {
    if selected.contains(&hash) {
        return Ok(());
    }
    ensure!(visiting.insert(hash), "mutation DAG contains a cycle");
    let event = events
        .get(&hash)
        .context("committed mutation head or parent is absent")?;
    validate_mutation(event, state)?;
    let EventPayload::Mutation { parents, .. } = &event.payload else {
        unreachable!()
    };
    for parent in parents {
        visit_mutation(*parent, events, state, visiting, selected)?;
    }
    visiting.remove(&hash);
    selected.insert(hash);
    Ok(())
}

fn current_epoch_mutations(
    events: &BTreeMap<Hash, &Event>,
    state: &TrustedState,
) -> Result<Vec<Hash>> {
    let mut valid = BTreeSet::new();
    loop {
        let before = valid.len();
        for (hash, event) in events {
            if valid.contains(hash) || validate_mutation(event, state).is_err() {
                continue;
            }
            let EventPayload::Mutation { parents, .. } = &event.payload else {
                continue;
            };
            if parents.iter().all(|parent| valid.contains(parent)) {
                valid.insert(*hash);
            }
        }
        if valid.len() == before {
            break;
        }
    }
    topological_mutations(&valid, events)
}

fn topological_mutations(
    selected: &BTreeSet<Hash>,
    events: &BTreeMap<Hash, &Event>,
) -> Result<Vec<Hash>> {
    let mut indegree = BTreeMap::new();
    let mut children = BTreeMap::<Hash, Vec<Hash>>::new();
    for hash in selected {
        let EventPayload::Mutation { parents, .. } = &events[hash].payload else {
            bail!("mutation closure contains a non-mutation")
        };
        indegree.insert(
            *hash,
            parents
                .iter()
                .filter(|parent| selected.contains(*parent))
                .count(),
        );
        for parent in parents.iter().filter(|parent| selected.contains(*parent)) {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(hash, degree)| (*degree == 0).then_some(*hash))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(selected.len());
    while let Some(hash) = ready.pop_first() {
        ordered.push(hash);
        for child in children.get(&hash).into_iter().flatten() {
            let degree = indegree.get_mut(child).expect("child was indexed");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(*child);
            }
        }
    }
    ensure!(
        ordered.len() == selected.len(),
        "mutation DAG contains a cycle"
    );
    Ok(ordered)
}

fn is_ancestor(ancestor: Hash, descendant: Hash, parents: &BTreeMap<Hash, Vec<Hash>>) -> bool {
    let mut pending = vec![descendant];
    let mut seen = BTreeSet::new();
    while let Some(hash) = pending.pop() {
        if hash == ancestor {
            return true;
        }
        if seen.insert(hash) {
            pending.extend(parents.get(&hash).into_iter().flatten().copied());
        }
    }
    false
}

fn classify_inert_events(
    state: &mut TrustedState,
    events_by_hash: &BTreeMap<Hash, &Event>,
    trusted_hashes: &BTreeSet<Hash>,
) {
    for (hash, event) in events_by_hash {
        if trusted_hashes.contains(hash) {
            continue;
        }
        match &event.payload {
            EventPayload::Genesis(_) => state
                .diagnostics
                .push("additional Genesis event is inert".into()),
            EventPayload::Mutation { epoch_number, .. }
                if *epoch_number < state.membership_epoch =>
            {
                state.diagnostics.push(format!(
                    "stale mutation {} was not committed by its closing membership epoch",
                    hex::encode_upper(&hash[..8])
                ))
            }
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
    if let Some(local) = &options.local_checkpoint {
        let trusted = state
            .trusted_event_hashes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        ensure!(
            local.iter().all(|hash| trusted.contains(hash)),
            "ordinary vault rollback or mutation omission detected by local freshness checkpoint"
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
        crypto::{encrypt_mutation, encrypt_snapshot, random_epoch_key, wrap_epoch_key},
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
            previous_epoch_heads: Vec::new(),
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
        mutation_with_parents(epoch_number, marker, Vec::new())
    }

    fn mutation_with_parents(epoch_number: u64, marker: u8, parents: Vec<Hash>) -> EventPayload {
        EventPayload::Mutation {
            epoch_number,
            parents,
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
    fn replay_follows_mutation_dag_when_physical_records_are_out_of_order() {
        let mut alice = identity(13, "Alice");
        let key = random_epoch_key();
        let genesis = genesis(&mut alice, &key);
        let control = trust_after(&genesis);
        let first = sign_event(&mut alice, control, mutation(1, 4));
        let second = sign_event(
            &mut alice,
            control,
            mutation_with_parents(1, 5, vec![first.event_hash().unwrap()]),
        );
        let state = derive_trusted_state(
            &[genesis, second.clone(), first.clone()],
            &DeriveOptions::default(),
        )
        .unwrap();
        assert_eq!(state.trusted_event_hashes.len(), 3);
        assert_eq!(state.trusted_event_hashes[1], first.event_hash().unwrap());
        assert_eq!(state.trusted_event_hashes[2], second.event_hash().unwrap());
        assert_eq!(state.mutation_heads, vec![second.event_hash().unwrap()]);
    }

    #[test]
    fn concurrent_authorized_mutations_merge_without_a_membership_fork() {
        let mut alice = identity(3, "Alice");
        let key = random_epoch_key();
        let genesis = genesis(&mut alice, &key);
        let control = trust_after(&genesis);
        let first = sign_event(&mut alice, control, mutation(1, 6));
        let second = sign_event(&mut alice, control, mutation(1, 7));
        let first_hash = first.event_hash().unwrap();
        let second_hash = second.event_hash().unwrap();
        let state =
            derive_trusted_state(&[genesis, first, second], &DeriveOptions::default()).unwrap();
        assert!(state.fork.is_none());
        assert_eq!(state.trusted_event_hashes.len(), 3);
        assert_eq!(state.mutation_heads, {
            let mut heads = vec![first_hash, second_hash];
            heads.sort();
            heads
        });
    }

    #[test]
    fn concurrent_changes_to_one_key_have_a_deterministic_winner() {
        let mut alice = identity(31, "Alice");
        let mut bob = identity(32, "Bob");
        let key = random_epoch_key();
        let first_epoch = epoch(1, &[(&alice, Role::Owner), (&bob, Role::Member)], &key);
        let genesis = sign_event(&mut alice, [0; 32], EventPayload::Genesis(first_epoch));
        let control = trust_after(&genesis);

        let make_put = |value: &str| {
            let (nonce, ciphertext) = encrypt_mutation(
                &[1; 32],
                1,
                &DecryptedMutation::Put {
                    key: "TOKEN".into(),
                    value: VaultValue::Text(value.into()),
                },
                &key,
            )
            .unwrap();
            EventPayload::Mutation {
                epoch_number: 1,
                parents: Vec::new(),
                nonce,
                ciphertext,
            }
        };
        let first = sign_event(&mut alice, control, make_put("alice"));
        let second = sign_event(&mut bob, control, make_put("bob"));
        let winner = if first.event_hash().unwrap() > second.event_hash().unwrap() {
            "alice"
        } else {
            "bob"
        };

        let left = derive_trusted_state(
            &[genesis.clone(), first.clone(), second.clone()],
            &DeriveOptions::default(),
        )
        .unwrap();
        let right =
            derive_trusted_state(&[genesis, second, first], &DeriveOptions::default()).unwrap();
        assert_eq!(left.mutation_heads, right.mutation_heads);
        assert_eq!(
            left.unlock_values(&key).unwrap().get("TOKEN"),
            Some(&VaultValue::Text(winner.into()))
        );
        assert_eq!(
            left.unlock_values(&key).unwrap(),
            right.unlock_values(&key).unwrap()
        );
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
                local_checkpoint: Some(vec![[0x55; 32]]),
                ..DeriveOptions::default()
            }
        )
        .is_err());
    }
}
