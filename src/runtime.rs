use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::{Cli, Command},
    crypto::{self, random_epoch_key, unwrap_epoch_key, VaultValue},
    event::{
        EpochMember, Event, EventLog, EventPayload, Hash, MemberIdentity, MembershipEpoch, Role,
    },
    git::{self, GitRepository, StoredLog},
    identity::{
        self, DeviceIdentity, DiscoveredIdentity, IdentityOperation, IdentitySession, IdentityState,
    },
    invitation::{self, ClientSessionState},
    state::{derive_trusted_state, DeriveOptions, TrustedState},
    terminal::{
        choose_identity, choose_option, discard_pending_input, discover_identities, event_to_input,
        identity_backend, prompt_line, require_terminal, with_terminal,
    },
    tui::{Effect, VaultUi},
};
use anyhow::{bail, ensure, Context, Result};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub fn run(cli: Cli) -> Result<()> {
    git::validate_vault_name(&cli.vault)?;
    let repository = GitRepository::discover(".")?;

    if let Some(Command::Fetch { remote }) = &cli.command {
        return fetch_and_advance(&repository, &cli.vault, remote);
    }
    if let Some(Command::Push { remote }) = &cli.command {
        repository.push_vault(remote, &cli.vault)?;
        println!("Pushed refs/vaults/{} to {remote}", cli.vault);
        return Ok(());
    }

    let stored = repository.read_vault(&cli.vault)?;
    if matches!(cli.command, Some(Command::Verify)) {
        let stored = stored.with_context(|| format!("vault {:?} does not exist", cli.vault))?;
        let state = derive_with_checkpoints(&repository, &cli.vault, &stored.log, None)?;
        print_verification(&stored, &state);
        return Ok(());
    }
    if let Some(Command::RequestAccess {
        invitation,
        name,
        phrase_stdin,
    }) = &cli.command
    {
        return request_access(
            &repository,
            &cli.vault,
            stored.context("vault does not exist")?,
            cli.identity.as_deref(),
            invitation,
            name,
            *phrase_stdin,
        );
    }
    if let Some(Command::ContinueRequest {
        proposal,
        phrase_stdin,
    }) = &cli.command
    {
        return continue_request(
            &repository,
            &cli.vault,
            stored.context("vault does not exist")?,
            cli.identity.as_deref(),
            proposal,
            *phrase_stdin,
        );
    }
    if let Some(Command::ConfirmAccess { proposal }) = &cli.command {
        return confirm_access(
            &repository,
            &cli.vault,
            stored.context("vault does not exist")?,
            cli.identity.as_deref(),
            proposal,
        )
        .map(|_| ());
    }
    if cli.command.is_none() {
        if let Some(stored) = stored.clone() {
            return run_interactive_existing(
                &repository,
                &cli.vault,
                stored,
                cli.identity.as_deref(),
            );
        }
    }

    let mut session = match stored {
        Some(stored) => unlock_vault(&repository, &cli.vault, stored, cli.identity.as_deref())?,
        None => {
            ensure!(
                !matches!(cli.command, Some(Command::Members)),
                "vault {:?} does not exist",
                cli.vault
            );
            create_vault(&repository, &cli.vault, cli.identity.as_deref())?
        }
    };
    match cli.command {
        Some(Command::List) => {
            for key in session.values.keys() {
                println!("{key}");
            }
            Ok(())
        }
        Some(Command::Get { key }) => {
            println!(
                "{}",
                session
                    .values
                    .get(&key)
                    .with_context(|| format!("secret {key:?} does not exist"))?
                    .display()
            );
            Ok(())
        }
        Some(Command::Set { key, r#type, stdin }) => {
            let mut input = if stdin {
                read_stdin_value("secret value")?
            } else {
                Zeroizing::new(
                    rpassword::prompt_password("Secret value: ")
                        .context("failed to read secret value")?,
                )
            };
            let value = VaultValue::parse(r#type.into(), std::mem::take(&mut *input))?;
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.append_put(key, value)?;
            Ok(())
        }
        Some(Command::Delete { key }) => {
            ensure!(
                session.values.contains_key(&key),
                "secret {key:?} does not exist"
            );
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.append_delete(key)?;
            Ok(())
        }
        Some(Command::Members) => {
            print_members(&session.state);
            Ok(())
        }
        Some(Command::Invite { minutes, words }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            let (invitation_id, mut phrase) = session.create_invitation(minutes, words)?;
            println!("{}", phrase.as_str());
            eprintln!("Invitation ID: {}", hex::encode_upper(invitation_id));
            phrase.zeroize();
            Ok(())
        }
        Some(Command::CloseInvitation { invitation }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.close_invitation(&invitation)
        }
        Some(Command::Respond { proposal }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            let response = session.respond_to_proposal(&proposal)?;
            println!("{}", hex::encode_upper(response));
            Ok(())
        }
        Some(Command::Approve { proposal }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.approve_proposal(&proposal)
        }
        Some(Command::RemoveMember { member }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.remove_member(&member)
        }
        Some(Command::SetRole { member, role }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.set_role(&member, role.into())
        }
        Some(
            Command::Verify
            | Command::Fetch { .. }
            | Command::Push { .. }
            | Command::RequestAccess { .. }
            | Command::ContinueRequest { .. }
            | Command::ConfirmAccess { .. },
        ) => unreachable!(),
        None => session.run_tui(),
    }
}

struct OpenVault {
    repository: GitRepository,
    vault_name: String,
    commit_oid: String,
    log: EventLog,
    state: TrustedState,
    values: BTreeMap<String, VaultValue>,
    epoch_key: crypto::EpochKey,
    identity: Box<dyn IdentitySession>,
}

impl OpenVault {
    fn append_put(&mut self, key: String, value: VaultValue) -> Result<()> {
        let (nonce, ciphertext) = crypto::encrypt_put(
            &self.state.vault_id,
            self.state.membership_epoch,
            &key,
            &value,
            &self.epoch_key,
        )?;
        self.append_payload(
            EventPayload::Put {
                epoch_number: self.state.membership_epoch,
                key: key.clone(),
                value_type: value.value_type(),
                nonce,
                ciphertext,
            },
            "append Put event",
        )?;
        self.values.insert(key, value);
        Ok(())
    }

    fn append_delete(&mut self, key: String) -> Result<()> {
        self.append_payload(
            EventPayload::Delete {
                epoch_number: self.state.membership_epoch,
                key: key.clone(),
            },
            "append Delete event",
        )?;
        self.values.remove(&key);
        Ok(())
    }

    fn create_invitation(
        &mut self,
        minutes: u64,
        words: usize,
    ) -> Result<([u8; 16], Zeroizing<String>)> {
        ensure!(
            (1..=10_080).contains(&minutes),
            "invitation duration must be 1–10080 minutes"
        );
        let phrase = invitation::generate_phrase(words)?;
        let mut invitation_id = [0u8; 16];
        OsRng.fill_bytes(&mut invitation_id);
        let expires_at = now_unix()
            .checked_add(minutes.saturating_mul(60))
            .context("invitation expiration overflow")?;
        let pake_message = invitation::create_registration(
            &self.state.vault_id,
            self.state.membership_epoch,
            &self.state.current_trust_hash,
            &invitation_id,
            &phrase,
            &self.epoch_key,
        )?;
        self.append_payload(
            EventPayload::CreateInvitation {
                epoch_number: self.state.membership_epoch,
                invitation_id,
                expires_at,
                pake_message,
            },
            "create OPAQUE invitation",
        )?;
        Ok((invitation_id, phrase))
    }

    fn close_invitation(&mut self, selector: &str) -> Result<()> {
        let invitation_id = select_invitation(&self.state, selector)?.invitation_id;
        self.append_payload(
            EventPayload::CloseInvitation { invitation_id },
            "close invitation",
        )
    }

    fn respond_to_proposal(&mut self, selector: &str) -> Result<Hash> {
        let proposal = select_proposal(&self.state, selector, false)?.clone();
        ensure!(
            proposal.response_event_hash.is_none(),
            "proposal already contains an OPAQUE finalization"
        );
        ensure!(
            !self
                .state
                .invitation_responses
                .values()
                .any(|response| response.proposal_event_hash == proposal.event_hash),
            "proposal already has an owner response"
        );
        let invitation = self
            .state
            .active_invitations
            .get(&proposal.invitation_id)
            .context("proposal invitation is no longer active")?;
        let event = find_event(&self.log, &proposal.event_hash)?;
        let EventPayload::ProposeUser { pake_message, .. } = &event.payload else {
            unreachable!()
        };
        let pake_response = invitation::create_server_response(
            &self.state.vault_id,
            invitation,
            &proposal.event_hash,
            &proposal.identity,
            pake_message,
            &self.epoch_key,
        )?;
        self.append_payload(
            EventPayload::InvitationResponse {
                epoch_number: self.state.membership_epoch,
                invitation_id: proposal.invitation_id,
                proposal_event_hash: proposal.event_hash,
                pake_message: pake_response,
            },
            "respond to OPAQUE proposal",
        )?;
        let response = self
            .state
            .invitation_responses
            .values()
            .find(|response| response.proposal_event_hash == proposal.event_hash)
            .context("trusted response was not derived after append")?;
        Ok(response.event_hash)
    }

    fn approve_proposal(&mut self, selector: &str) -> Result<()> {
        let proposal = select_proposal(&self.state, selector, true)?.clone();
        let response_hash = proposal
            .response_event_hash
            .context("proposal has not completed the OPAQUE exchange")?;
        let response = self
            .state
            .invitation_responses
            .get(&response_hash)
            .context("proposal references an untrusted OPAQUE response")?;
        let invitation = self
            .state
            .active_invitations
            .get(&proposal.invitation_id)
            .context("proposal invitation is no longer active")?;
        let event = find_event(&self.log, &proposal.event_hash)?;
        let EventPayload::ProposeUser { pake_message, .. } = &event.payload else {
            unreachable!()
        };
        let (_authentication, session_key) = invitation::authenticate_final_proposal(
            &self.state.vault_id,
            invitation,
            response,
            pake_message,
            &proposal.identity,
            &self.epoch_key,
        )?;
        ensure!(
            self.state
                .members
                .iter()
                .all(|member| member.identity.signing_public_key
                    != proposal.identity.signing_public_key
                    && member.identity.encryption_public_key
                        != proposal.identity.encryption_public_key),
            "proposal identity is already a trusted member"
        );
        let epoch_number = self.state.membership_epoch + 1;
        let next_epoch_key = random_epoch_key();
        let mut members = self
            .state
            .members
            .iter()
            .map(|member| (member.identity.clone(), member.role))
            .collect::<Vec<_>>();
        members.push((proposal.identity.clone(), Role::Reader));
        let members = members
            .into_iter()
            .map(|(identity, role)| {
                Ok(EpochMember {
                    wrapped_epoch_key: crypto::wrap_epoch_key(
                        &self.state.vault_id,
                        epoch_number,
                        &identity,
                        &next_epoch_key,
                    )?,
                    identity,
                    role,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut epoch = MembershipEpoch {
            epoch_number,
            members,
            snapshot: crypto::encrypt_snapshot(
                &self.state.vault_id,
                epoch_number,
                &self.values,
                &next_epoch_key,
            )?,
            accepted_proposal: Some(proposal.event_hash),
            admission_confirmation: Some([0; 32]),
        };
        epoch.admission_confirmation = Some(invitation::admission_confirmation(
            &session_key,
            &self.state.vault_id,
            &self.state.current_trust_hash,
            &epoch,
        )?);
        self.append_payload(
            EventPayload::MembershipEpoch(epoch),
            "admit OPAQUE-authenticated member",
        )?;
        self.epoch_key = next_epoch_key;
        let _ = self
            .identity
            .write_trust_record(&self.state.trusted_checkpoint());
        Ok(())
    }

    fn remove_member(&mut self, selector: &str) -> Result<()> {
        let index = select_member_index(&self.state.members, selector)?;
        self.remove_member_at(index)
    }

    fn remove_member_by_signing_key(&mut self, signing_public_key: &[u8; 32]) -> Result<()> {
        let index = self
            .state
            .members
            .iter()
            .position(|member| &member.identity.signing_public_key == signing_public_key)
            .context("member no longer exists")?;
        self.remove_member_at(index)
    }

    fn remove_member_at(&mut self, index: usize) -> Result<()> {
        ensure!(
            self.state.members.len() > 1,
            "cannot remove the final member"
        );
        let mut members = self.state.members.clone();
        members.remove(index);
        ensure!(
            members.iter().any(|member| member.role == Role::Owner),
            "cannot remove the final owner"
        );
        self.rotate_membership(members, "remove member")
    }

    fn set_role(&mut self, selector: &str, role: Role) -> Result<()> {
        let index = select_member_index(&self.state.members, selector)?;
        ensure!(
            self.state.members[index].role != role,
            "member already has that role"
        );
        let mut members = self.state.members.clone();
        members[index].role = role;
        ensure!(
            members.iter().any(|member| member.role == Role::Owner),
            "cannot demote the final owner"
        );
        self.rotate_membership(members, "set member role")
    }

    fn rotate_membership(&mut self, old_members: Vec<EpochMember>, message: &str) -> Result<()> {
        let epoch_number = self.state.membership_epoch + 1;
        let next_epoch_key = random_epoch_key();
        let members = old_members
            .into_iter()
            .map(|member| {
                Ok(EpochMember {
                    wrapped_epoch_key: crypto::wrap_epoch_key(
                        &self.state.vault_id,
                        epoch_number,
                        &member.identity,
                        &next_epoch_key,
                    )?,
                    identity: member.identity,
                    role: member.role,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let epoch = MembershipEpoch {
            epoch_number,
            members,
            snapshot: crypto::encrypt_snapshot(
                &self.state.vault_id,
                epoch_number,
                &self.values,
                &next_epoch_key,
            )?,
            accepted_proposal: None,
            admission_confirmation: None,
        };
        self.append_payload(EventPayload::MembershipEpoch(epoch), message)?;
        self.epoch_key = next_epoch_key;
        let _ = self
            .identity
            .write_trust_record(&self.state.trusted_checkpoint());
        Ok(())
    }

    fn append_payload(&mut self, payload: EventPayload, message: &str) -> Result<()> {
        ensure!(
            self.state.fork.is_none(),
            "cannot append while a trusted fork is unresolved"
        );
        ensure!(
            self.state
                .member_for_signing_key(&self.identity.identity().signing_public_key)
                .is_some_and(|member| member.role == Role::Owner),
            "the selected identity is not authorized to append this event type"
        );
        let event = Event::unsigned(
            self.state.vault_id,
            self.state.current_trust_hash,
            self.identity.identity().signing_public_key,
            payload,
        )
        .sign(self.identity.as_mut())?;
        let event_hash = event.event_hash()?;
        let mut next_log = self.log.clone();
        next_log.append(event)?;
        let next_state = derive_trusted_state(
            &next_log.events,
            &DeriveOptions {
                now: now_unix(),
                local_checkpoint: Some(self.state.current_trust_hash),
                ..DeriveOptions::default()
            },
        )?;
        ensure!(
            next_state.fork.is_none(),
            "new event produced a trusted fork"
        );
        ensure!(
            next_state.trusted_event_hashes.contains(&event_hash),
            "the appended event was not authorized by the prior trusted state"
        );
        let next_commit = self.repository.append_vault_log(
            &self.vault_name,
            Some(&self.commit_oid),
            &next_log,
            message,
        )?;
        self.repository
            .write_local_checkpoint(&self.vault_name, &next_state.current_trust_hash)?;
        self.log = next_log;
        self.commit_oid = next_commit;
        self.state = next_state;
        Ok(())
    }

    fn run_tui(&mut self) -> Result<()> {
        require_terminal()?;
        let invitations = self.state.active_invitations.values().cloned().collect();
        let mut app = VaultUi::new(
            self.values.clone(),
            self.state.members.clone(),
            invitations,
            self.state.pending_proposals.clone(),
        );
        let mut outputs = Vec::new();
        let result = with_terminal(|terminal| loop {
            terminal.draw(|frame| app.draw(frame, self.repository.workdir(), &self.vault_name))?;
            let Some(input) = event_to_input()? else {
                continue;
            };
            let effect = app.input(input);
            let uses_signing_identity = matches!(
                effect,
                Effect::Put { .. }
                    | Effect::Delete { .. }
                    | Effect::RemoveMember { .. }
                    | Effect::CreateInvitation
                    | Effect::CloseInvitation { .. }
                    | Effect::RespondProposal { .. }
                    | Effect::ApproveProposal { .. }
            );
            if uses_signing_identity {
                if let Some(hint) = self.identity.interaction_hint(IdentityOperation::Sign) {
                    app.set_status(hint);
                    terminal.draw(|frame| {
                        app.draw(frame, self.repository.workdir(), &self.vault_name)
                    })?;
                }
            }
            match effect {
                Effect::None => {}
                Effect::Quit => break Ok(()),
                Effect::Output(value) => outputs.push(value),
                Effect::Put { key, value } => match self.append_put(key.clone(), value.clone()) {
                    Ok(()) => app.apply_put(key, value),
                    Err(error) => app.set_status(format!("Put not appended: {error:#}")),
                },
                Effect::Delete { key } => match self.append_delete(key.clone()) {
                    Ok(()) => app.apply_delete(&key),
                    Err(error) => app.set_status(format!("Delete not appended: {error:#}")),
                },
                Effect::RemoveMember { signing_public_key } => {
                    match self.remove_member_by_signing_key(&signing_public_key) {
                        Ok(()) => {
                            refresh_access_view(&mut app, &self.state);
                            app.set_status(
                                "Member removed; epoch key rotated; invitations invalidated",
                            );
                        }
                        Err(error) => {
                            app.set_status(format!("Member not removed: {error:#}"));
                        }
                    }
                }
                Effect::CreateInvitation => match self.create_invitation(30, 4) {
                    Ok((invitation_id, mut phrase)) => {
                        refresh_access_view(&mut app, &self.state);
                        app.set_status(format!(
                            "Invitation {} phrase: {}",
                            hex::encode_upper(&invitation_id[..4]),
                            phrase.as_str()
                        ));
                        phrase.zeroize();
                    }
                    Err(error) => app.set_status(format!("Invitation not created: {error:#}")),
                },
                Effect::CloseInvitation { invitation_id } => {
                    let selector = hex::encode_upper(invitation_id);
                    match self.close_invitation(&selector) {
                        Ok(()) => {
                            refresh_access_view(&mut app, &self.state);
                            app.set_status("Invitation closed");
                        }
                        Err(error) => app.set_status(format!("Invitation not closed: {error:#}")),
                    }
                }
                Effect::RespondProposal {
                    proposal_event_hash,
                } => {
                    let selector = hex::encode_upper(proposal_event_hash);
                    match self.respond_to_proposal(&selector) {
                        Ok(_) => {
                            refresh_access_view(&mut app, &self.state);
                            app.set_status("OPAQUE response appended; requester must continue");
                        }
                        Err(error) => app.set_status(format!("Proposal not answered: {error:#}")),
                    }
                }
                Effect::ApproveProposal {
                    proposal_event_hash,
                } => {
                    let selector = hex::encode_upper(proposal_event_hash);
                    match self.approve_proposal(&selector) {
                        Ok(()) => {
                            refresh_access_view(&mut app, &self.state);
                            app.set_status(
                                "Member admitted; epoch rotated; invitations invalidated",
                            );
                        }
                        Err(error) => app.set_status(format!("Proposal not approved: {error:#}")),
                    }
                }
            }
            if uses_signing_identity {
                discard_pending_input()?;
            }
        });
        drop(app);
        for output in outputs {
            println!("{output}");
        }
        result
    }
}

fn create_vault(
    repository: &GitRepository,
    vault_name: &str,
    requested_identity: Option<&str>,
) -> Result<OpenVault> {
    let discovered = discover_identities()?;
    let selected = choose_identity(
        discovered,
        requested_identity,
        true,
        true,
        "Select an identity for the new vault",
    )?;
    ensure!(
        selected.state.is_usable(),
        "selected identity is unavailable"
    );
    let backend = identity_backend(&selected.backend)?;
    let device = backend.provision(&selected)?;
    let ready = DiscoveredIdentity {
        backend: device.backend.clone(),
        locator: device.locator.clone(),
        display_name: device.display_name.clone(),
        detail: format!("identity {}", device.fingerprint()),
        state: IdentityState::Ready(device.clone()),
    };
    let mut session = backend.open(&ready)?;
    let mut vault_id = [0u8; 32];
    OsRng.fill_bytes(&mut vault_id);
    let epoch_key = random_epoch_key();
    let member_identity = member_identity(&device, format!("Primary — {}", device.display_name));
    let member = EpochMember {
        wrapped_epoch_key: crypto::wrap_epoch_key(&vault_id, 1, &member_identity, &epoch_key)?,
        identity: member_identity,
        role: Role::Owner,
    };
    let epoch = MembershipEpoch {
        epoch_number: 1,
        members: vec![member],
        snapshot: crypto::encrypt_snapshot(&vault_id, 1, &BTreeMap::new(), &epoch_key)?,
        accepted_proposal: None,
        admission_confirmation: None,
    };
    print_identity_hint(session.as_ref(), IdentityOperation::Sign);
    let genesis = Event::unsigned(
        vault_id,
        [0; 32],
        device.signing_public_key,
        EventPayload::Genesis(epoch),
    )
    .sign(session.as_mut())?;
    let mut log = EventLog::default();
    log.append(genesis)?;
    let commit_oid = repository.append_vault_log(vault_name, None, &log, "create vault")?;
    let state = derive_trusted_state(&log.events, &DeriveOptions::default())?;
    repository.write_local_checkpoint(vault_name, &state.current_trust_hash)?;
    if let Err(error) = session.write_trust_record(&state.trusted_checkpoint()) {
        eprintln!("Warning: hardware membership rollback checkpoint was not written: {error:#}");
    }
    eprintln!(
        "Created refs/vaults/{vault_name} for {} [{}]",
        device.display_name,
        device.fingerprint()
    );
    Ok(OpenVault {
        repository: repository.clone(),
        vault_name: vault_name.into(),
        commit_oid,
        log,
        state,
        values: BTreeMap::new(),
        epoch_key,
        identity: session,
    })
}

fn run_interactive_existing(
    repository: &GitRepository,
    vault_name: &str,
    stored: StoredLog,
    requested_identity: Option<&str>,
) -> Result<()> {
    let state = derive_with_checkpoints(repository, vault_name, &stored.log, None)?;
    ensure!(
        state.fork.is_none(),
        "cannot open a vault with an unresolved trusted fork"
    );
    let choices = discover_identities()?
        .into_iter()
        .map(|mut identity| {
            let access = match &identity.state {
                IdentityState::Ready(device) => state
                    .member_for_public_keys(
                        &device.signing_public_key,
                        &device.encryption_public_key,
                    )
                    .map(|member| format!("trusted {:?}", member.role))
                    .unwrap_or_else(|| "not trusted; invitation onboarding available".into()),
                IdentityState::Provisionable => {
                    "not provisioned; invitation onboarding available".into()
                }
                IdentityState::Unavailable(_) => "unavailable; not trusted".into(),
            };
            identity.detail = format!("{} — {access}", identity.detail);
            identity
        })
        .collect::<Vec<_>>();
    let selected = choose_identity(
        choices,
        requested_identity,
        true,
        true,
        "Select an identity",
    )?;
    ensure!(
        selected.state.is_usable(),
        "selected identity is unavailable"
    );
    let selector = selected.selector();
    if let IdentityState::Ready(device) = &selected.state {
        if let Some(final_hash) =
            admitted_local_proposal(repository, vault_name, &stored, &state, device)
        {
            let mut vault = confirm_access(
                repository,
                vault_name,
                stored,
                Some(&selector),
                &hex::encode_upper(final_hash),
            )?;
            return vault.run_tui();
        }
        if state
            .member_for_public_keys(&device.signing_public_key, &device.encryption_public_key)
            .is_some()
        {
            let mut vault = unlock_vault(repository, vault_name, stored, Some(&selector))?;
            return vault.run_tui();
        }
        let matching = state
            .pending_proposals
            .iter()
            .filter(|proposal| {
                proposal.identity.signing_public_key == device.signing_public_key
                    && proposal.identity.encryption_public_key == device.encryption_public_key
            })
            .collect::<Vec<_>>();
        if let Some(final_proposal) = matching
            .iter()
            .copied()
            .find(|proposal| proposal.response_event_hash.is_some())
        {
            println!(
                "Access proof {} is complete; an owner must approve it before this identity can open the vault.",
                hex::encode_upper(&final_proposal.event_hash[..8])
            );
            return Ok(());
        }
        if let Some(start) = matching
            .iter()
            .copied()
            .find(|proposal| proposal.owner_response_event_hash.is_some())
        {
            return continue_request(
                repository,
                vault_name,
                stored,
                Some(&selector),
                &hex::encode_upper(start.event_hash),
                false,
            );
        }
        if let Some(start) = matching.first() {
            println!(
                "Access request {} is waiting for an owner response.",
                hex::encode_upper(&start.event_hash[..8])
            );
            return Ok(());
        }
    }

    ensure!(
        !state.active_invitations.is_empty(),
        "this identity is not trusted and the vault has no active invitation"
    );
    let invitation_selector = choose_option(
        state
            .active_invitations
            .values()
            .map(|invitation| {
                let id = hex::encode_upper(invitation.invitation_id);
                (
                    id.clone(),
                    format!("{id}  expires {}", invitation.expires_at),
                )
            })
            .collect(),
        "Select an invitation",
    )?;
    let default_name = selected.display_name.clone();
    let entered_name = prompt_line(&format!("Member name [{default_name}]: "))?;
    let name = if entered_name.is_empty() {
        default_name
    } else {
        entered_name
    };
    request_access(
        repository,
        vault_name,
        stored,
        Some(&selector),
        &invitation_selector,
        &name,
        false,
    )
}

fn admitted_local_proposal(
    repository: &GitRepository,
    vault_name: &str,
    stored: &StoredLog,
    state: &TrustedState,
    device: &DeviceIdentity,
) -> Option<Hash> {
    stored.log.events.iter().rev().find_map(|event| {
        if !state
            .trusted_event_hashes
            .contains(&event.event_hash().ok()?)
        {
            return None;
        }
        let EventPayload::MembershipEpoch(epoch) = &event.payload else {
            return None;
        };
        let proposal_hash = epoch.accepted_proposal?;
        let proposal = find_event(&stored.log, &proposal_hash).ok()?;
        let EventPayload::ProposeUser { identity, .. } = &proposal.payload else {
            return None;
        };
        if identity.signing_public_key != device.signing_public_key
            || identity.encryption_public_key != device.encryption_public_key
            || repository
                .read_onboarding_state(vault_name, &proposal_hash)
                .is_err()
        {
            return None;
        }
        Some(proposal_hash)
    })
}

fn unlock_vault(
    repository: &GitRepository,
    vault_name: &str,
    stored: StoredLog,
    requested_identity: Option<&str>,
) -> Result<OpenVault> {
    let initial = derive_with_checkpoints(repository, vault_name, &stored.log, None)?;
    if let Some(fork) = &initial.fork {
        bail!(
            "trusted replay stopped at fork {} with candidates {}",
            hex::encode_upper(&fork.parent_trust_hash[..8]),
            fork.candidate_event_hashes
                .iter()
                .map(|hash| hex::encode_upper(&hash[..8]))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let choices = discover_identities()?
        .into_iter()
        .map(|mut identity| {
            let access = match &identity.state {
                IdentityState::Ready(device) => initial
                    .member_for_public_keys(
                        &device.signing_public_key,
                        &device.encryption_public_key,
                    )
                    .map(|member| format!("trusted {:?}", member.role))
                    .unwrap_or_else(|| "not trusted".into()),
                IdentityState::Provisionable => "not provisioned; not trusted".into(),
                IdentityState::Unavailable(_) => "unavailable; not trusted".into(),
            };
            identity.detail = format!("{} — {access}", identity.detail);
            identity
        })
        .collect::<Vec<_>>();
    let selected = choose_identity(
        choices,
        requested_identity,
        false,
        true,
        "Select an identity",
    )?;
    let IdentityState::Ready(device) = &selected.state else {
        bail!(
            "{} cannot open this vault: {}",
            selected.display_name,
            selected.state.description()
        );
    };
    ensure!(
        initial
            .member_for_public_keys(&device.signing_public_key, &device.encryption_public_key)
            .is_some(),
        "{} is not a trusted member of this vault",
        device.display_name
    );
    let backend = identity_backend(&selected.backend)?;
    let mut identity = backend.open(&selected)?;
    let hardware_checkpoint = identity.read_trust_record(&initial.vault_id)?;
    let state = derive_with_checkpoints(repository, vault_name, &stored.log, hardware_checkpoint)?;
    let member = state
        .member_for_public_keys(&device.signing_public_key, &device.encryption_public_key)
        .context("selected identity is not in the verified membership epoch")?;
    print_identity_hint(identity.as_ref(), IdentityOperation::Agree);
    let epoch_key = unwrap_epoch_key(
        &state.vault_id,
        state.membership_epoch,
        &member.identity,
        &member.wrapped_epoch_key,
        identity.as_mut(),
    )?;
    let values = state.unlock_values(&epoch_key)?;
    repository.write_local_checkpoint(vault_name, &state.current_trust_hash)?;
    Ok(OpenVault {
        repository: repository.clone(),
        vault_name: vault_name.into(),
        commit_oid: stored.commit_oid,
        log: stored.log,
        state,
        values,
        epoch_key,
        identity,
    })
}

fn request_access(
    repository: &GitRepository,
    vault_name: &str,
    stored: StoredLog,
    requested_identity: Option<&str>,
    invitation_selector: &str,
    name: &str,
    phrase_stdin: bool,
) -> Result<()> {
    let state = derive_with_checkpoints(repository, vault_name, &stored.log, None)?;
    ensure!(
        state.fork.is_none(),
        "cannot request access while a trusted fork is unresolved"
    );
    let invitation = select_invitation(&state, invitation_selector)?.clone();
    ensure!(
        invitation.expires_at >= now_unix(),
        "invitation has expired"
    );
    let selected = choose_identity(
        discover_identities()?,
        requested_identity,
        true,
        true,
        "Select an identity for the access request",
    )?;
    ensure!(
        selected.state.is_usable(),
        "selected identity is unavailable"
    );
    let backend = identity_backend(&selected.backend)?;
    let device = backend.provision(&selected)?;
    let ready = DiscoveredIdentity {
        backend: device.backend.clone(),
        locator: device.locator.clone(),
        display_name: device.display_name.clone(),
        detail: format!("identity {}", device.fingerprint()),
        state: IdentityState::Ready(device.clone()),
    };
    let mut identity = backend.open(&ready)?;
    let proposed = member_identity(&device, name.to_owned());
    let mut phrase = read_phrase(phrase_stdin)?;
    let (client_state, credential_request) =
        invitation::start_proposal(&invitation, proposed.clone(), &phrase)?;
    phrase.zeroize();
    print_identity_hint(identity.as_ref(), IdentityOperation::Sign);
    let event = Event::unsigned(
        state.vault_id,
        state.current_trust_hash,
        device.signing_public_key,
        EventPayload::ProposeUser {
            invitation_id: invitation.invitation_id,
            identity: proposed,
            response_event_hash: None,
            pake_message: credential_request,
        },
    )
    .sign(identity.as_mut())?;
    let event_hash = event.event_hash()?;
    append_candidate(
        repository,
        vault_name,
        stored,
        event,
        "start OPAQUE access proposal",
    )?;
    let mut encoded = invitation::encode_client_start_state(&client_state)?;
    repository.write_onboarding_state(vault_name, &event_hash, &encoded)?;
    encoded.zeroize();
    println!("{}", hex::encode_upper(event_hash));
    eprintln!(
        "Access proposal started; an owner must run `git vault {vault_name} respond {}`.",
        hex::encode_upper(&event_hash[..8])
    );
    Ok(())
}

fn continue_request(
    repository: &GitRepository,
    vault_name: &str,
    stored: StoredLog,
    requested_identity: Option<&str>,
    proposal_selector: &str,
    phrase_stdin: bool,
) -> Result<()> {
    let state = derive_with_checkpoints(repository, vault_name, &stored.log, None)?;
    ensure!(
        state.fork.is_none(),
        "cannot continue access while a trusted fork is unresolved"
    );
    let proposal = select_proposal(&state, proposal_selector, false)?.clone();
    ensure!(
        proposal.response_event_hash.is_none(),
        "selected proposal is already final"
    );
    let response = state
        .invitation_responses
        .values()
        .find(|response| response.proposal_event_hash == proposal.event_hash)
        .context("an owner has not responded to this proposal yet")?
        .clone();
    let invitation = state
        .active_invitations
        .get(&proposal.invitation_id)
        .context("proposal invitation is no longer active")?
        .clone();
    let mut local =
        Zeroizing::new(repository.read_onboarding_state(vault_name, &proposal.event_hash)?);
    let client_state = invitation::decode_client_start_state(&local)?;
    local.zeroize();
    ensure!(
        client_state.proposal_identity == proposal.identity,
        "local proposal identity mismatch"
    );
    let selected = choose_identity(
        discover_identities()?,
        requested_identity,
        false,
        true,
        "Select the identity that started the request",
    )?;
    let IdentityState::Ready(device) = &selected.state else {
        bail!("selected identity is not provisioned");
    };
    ensure!(
        device.signing_public_key == proposal.identity.signing_public_key
            && device.encryption_public_key == proposal.identity.encryption_public_key,
        "selected identity did not start this proposal"
    );
    let backend = identity_backend(&selected.backend)?;
    let mut identity = backend.open(&selected)?;
    let mut phrase = read_phrase(phrase_stdin)?;
    let (finalization, session_key) = invitation::finish_proposal(
        &state.vault_id,
        &invitation,
        &proposal.event_hash,
        &response,
        client_state,
        &phrase,
    )?;
    phrase.zeroize();
    print_identity_hint(identity.as_ref(), IdentityOperation::Sign);
    let event = Event::unsigned(
        state.vault_id,
        state.current_trust_hash,
        device.signing_public_key,
        EventPayload::ProposeUser {
            invitation_id: proposal.invitation_id,
            identity: proposal.identity.clone(),
            response_event_hash: Some(response.event_hash),
            pake_message: finalization,
        },
    )
    .sign(identity.as_mut())?;
    let final_hash = event.event_hash()?;
    append_candidate(
        repository,
        vault_name,
        stored,
        event,
        "finish OPAQUE access proposal",
    )?;
    let session_state = ClientSessionState {
        invitation_id: proposal.invitation_id,
        invitation_event_hash: invitation.create_event_hash,
        response_event_hash: response.event_hash,
        final_proposal_hash: final_hash,
        proposal_identity: proposal.identity,
        session_key,
    };
    let mut encoded = invitation::encode_client_session_state(&session_state)?;
    repository.write_onboarding_state(vault_name, &final_hash, &encoded)?;
    encoded.zeroize();
    repository.delete_onboarding_state(vault_name, &proposal.event_hash)?;
    println!("{}", hex::encode_upper(final_hash));
    eprintln!(
        "OPAQUE exchange complete; an owner must run `git vault {vault_name} approve {}`.",
        hex::encode_upper(&final_hash[..8])
    );
    Ok(())
}

fn confirm_access(
    repository: &GitRepository,
    vault_name: &str,
    stored: StoredLog,
    requested_identity: Option<&str>,
    proposal_selector: &str,
) -> Result<OpenVault> {
    let final_event = select_event(&stored.log, proposal_selector, |event| {
        matches!(
            event.payload,
            EventPayload::ProposeUser {
                response_event_hash: Some(_),
                ..
            }
        )
    })?;
    let final_hash = final_event.event_hash()?;
    let mut local = Zeroizing::new(repository.read_onboarding_state(vault_name, &final_hash)?);
    let session = invitation::decode_client_session_state(&local)?;
    local.zeroize();
    ensure!(
        session.final_proposal_hash == final_hash,
        "local OPAQUE session mismatch"
    );
    let state = derive_with_checkpoints(repository, vault_name, &stored.log, None)?;
    let admission_event = stored
        .log
        .events
        .iter()
        .find(|event| {
            state
                .trusted_event_hashes
                .contains(&event.event_hash().unwrap_or([0; 32]))
                && matches!(
                    &event.payload,
                    EventPayload::MembershipEpoch(epoch)
                        if epoch.accepted_proposal == Some(final_hash)
                )
        })
        .context("the proposal has not been admitted by a trusted owner")?;
    let EventPayload::MembershipEpoch(epoch) = &admission_event.payload else {
        unreachable!()
    };
    invitation::verify_admission_confirmation(
        &session.session_key,
        &state.vault_id,
        &admission_event.parent_trust_hash,
        epoch,
    )?;
    ensure!(
        state
            .member_for_public_keys(
                &session.proposal_identity.signing_public_key,
                &session.proposal_identity.encryption_public_key,
            )
            .is_some(),
        "admission event did not add the proposed identity"
    );
    let selected = choose_identity(
        discover_identities()?,
        requested_identity,
        false,
        true,
        "Select the newly admitted identity",
    )?;
    let IdentityState::Ready(device) = &selected.state else {
        bail!("selected identity is not provisioned");
    };
    ensure!(
        device.signing_public_key == session.proposal_identity.signing_public_key
            && device.encryption_public_key == session.proposal_identity.encryption_public_key,
        "selected identity is not the admitted identity"
    );
    let backend = identity_backend(&selected.backend)?;
    let mut identity = backend.open(&selected)?;
    let member = state
        .member_for_public_keys(&device.signing_public_key, &device.encryption_public_key)
        .context("admitted identity is absent from the current membership epoch")?;
    print_identity_hint(identity.as_ref(), IdentityOperation::Agree);
    let epoch_key = unwrap_epoch_key(
        &state.vault_id,
        state.membership_epoch,
        &member.identity,
        &member.wrapped_epoch_key,
        identity.as_mut(),
    )?;
    let values = state.unlock_values(&epoch_key)?;
    if let Err(error) = identity.write_trust_record(&state.trusted_checkpoint()) {
        eprintln!("Warning: hardware membership rollback checkpoint was not written: {error:#}");
    }
    repository.write_local_checkpoint(vault_name, &state.current_trust_hash)?;
    repository.delete_onboarding_state(vault_name, &final_hash)?;
    eprintln!(
        "Admission confirmed for {}.",
        session.proposal_identity.name
    );
    Ok(OpenVault {
        repository: repository.clone(),
        vault_name: vault_name.into(),
        commit_oid: stored.commit_oid,
        log: stored.log,
        state,
        values,
        epoch_key,
        identity,
    })
}

fn append_candidate(
    repository: &GitRepository,
    vault_name: &str,
    stored: StoredLog,
    event: Event,
    message: &str,
) -> Result<StoredLog> {
    let before = derive_trusted_state(
        &stored.log.events,
        &DeriveOptions {
            now: now_unix(),
            ..DeriveOptions::default()
        },
    )?;
    ensure!(
        before.fork.is_none(),
        "cannot append while a trusted fork is unresolved"
    );
    ensure!(
        event.vault_id == before.vault_id,
        "candidate event is for another vault"
    );
    let mut log = stored.log.clone();
    log.append(event)?;
    let after = derive_trusted_state(
        &log.events,
        &DeriveOptions {
            now: now_unix(),
            ..DeriveOptions::default()
        },
    )?;
    ensure!(
        after.current_trust_hash == before.current_trust_hash && after.fork.is_none(),
        "untrusted candidate unexpectedly changed the trusted projection"
    );
    let commit_oid =
        repository.append_vault_log(vault_name, Some(&stored.commit_oid), &log, message)?;
    Ok(StoredLog { commit_oid, log })
}

fn read_phrase(stdin: bool) -> Result<Zeroizing<String>> {
    let phrase = if stdin {
        read_stdin_value("invitation phrase")?
    } else {
        Zeroizing::new(
            rpassword::prompt_password("Invitation phrase: ")
                .context("failed to read invitation phrase")?,
        )
    };
    invitation::validate_phrase(&phrase)?;
    Ok(phrase)
}

fn derive_with_checkpoints(
    repository: &GitRepository,
    vault_name: &str,
    log: &EventLog,
    hardware_checkpoint: Option<identity::VaultTrustRecord>,
) -> Result<TrustedState> {
    let local_checkpoint = repository.read_local_checkpoint(vault_name)?;
    let state = derive_trusted_state(
        &log.events,
        &DeriveOptions {
            now: now_unix(),
            hardware_checkpoint,
            local_checkpoint,
            invitation_authenticated_proposals: BTreeMap::new(),
        },
    )?;
    Ok(state)
}

fn fetch_and_advance(repository: &GitRepository, vault: &str, remote: &str) -> Result<()> {
    let current = repository.read_vault(vault)?;
    repository.fetch_vault(remote, vault)?;
    let remote_log = repository
        .read_remote_vault(remote, vault)?
        .with_context(|| format!("remote {remote:?} has no vault {vault:?}"))?;
    let state = derive_with_checkpoints(repository, vault, &remote_log.log, None)?;
    ensure!(
        state.fork.is_none(),
        "fetched vault contains an unresolved trusted fork"
    );
    repository.advance_vault_ref(
        vault,
        current.as_ref().map(|stored| stored.commit_oid.as_str()),
        &remote_log.commit_oid,
    )?;
    repository.write_local_checkpoint(vault, &state.current_trust_hash)?;
    println!(
        "Verified and advanced refs/vaults/{vault} to trusted hash {}",
        hex::encode_upper(&state.current_trust_hash[..8])
    );
    Ok(())
}

fn print_verification(stored: &StoredLog, state: &TrustedState) {
    println!("commit             {}", stored.commit_oid);
    println!("vault ID           {}", hex::encode_upper(state.vault_id));
    println!(
        "trusted hash       {}",
        hex::encode_upper(state.current_trust_hash)
    );
    println!("membership epoch   {}", state.membership_epoch);
    println!("projection level   {:?}", state.validation);
    println!("trusted events     {}", state.trusted_event_hashes.len());
    println!("raw valid events   {}", stored.log.events.len());
    println!("invalid records    {}", stored.log.diagnostics.len());
    println!("pending proposals  {}", state.pending_proposals.len());
    println!(
        "fork               {}",
        if state.fork.is_some() { "yes" } else { "no" }
    );
    for diagnostic in stored.log.diagnostics.iter().chain(&state.diagnostics) {
        println!("diagnostic         {diagnostic}");
    }
}

fn refresh_access_view(app: &mut VaultUi, state: &TrustedState) {
    app.refresh_access(
        state.members.clone(),
        state.active_invitations.values().cloned().collect(),
        state.pending_proposals.clone(),
    );
}

fn select_invitation<'a>(
    state: &'a TrustedState,
    selector: &str,
) -> Result<&'a crate::state::InvitationState> {
    let normalized = selector.to_ascii_uppercase();
    let matches = state
        .active_invitations
        .values()
        .filter(|invitation| hex::encode_upper(invitation.invitation_id).starts_with(&normalized))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [invitation] => Ok(*invitation),
        [] => bail!("no active invitation matches {selector:?}"),
        _ => bail!("invitation selector {selector:?} is ambiguous"),
    }
}

fn select_proposal<'a>(
    state: &'a TrustedState,
    selector: &str,
    require_final: bool,
) -> Result<&'a crate::state::PendingProposal> {
    let normalized = selector.to_ascii_uppercase();
    let matches = state
        .pending_proposals
        .iter()
        .filter(|proposal| {
            proposal.response_event_hash.is_some() == require_final
                && hex::encode_upper(proposal.event_hash).starts_with(&normalized)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [proposal] => Ok(*proposal),
        [] => bail!(
            "no {} proposal matches {selector:?}",
            if require_final { "final" } else { "starting" }
        ),
        _ => bail!("proposal selector {selector:?} is ambiguous"),
    }
}

fn select_event<'a>(
    log: &'a EventLog,
    selector: &str,
    predicate: impl Fn(&Event) -> bool,
) -> Result<&'a Event> {
    let normalized = selector.to_ascii_uppercase();
    let matches = log
        .events
        .iter()
        .filter(|event| {
            predicate(event)
                && event
                    .event_hash()
                    .is_ok_and(|hash| hex::encode_upper(hash).starts_with(&normalized))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [event] => Ok(*event),
        [] => bail!("no event matches {selector:?}"),
        _ => bail!("event selector {selector:?} is ambiguous"),
    }
}

fn find_event<'a>(log: &'a EventLog, hash: &Hash) -> Result<&'a Event> {
    log.events
        .iter()
        .find(|event| event.event_hash().ok().as_ref() == Some(hash))
        .context("referenced event is absent from the log")
}

fn select_member_index(members: &[EpochMember], selector: &str) -> Result<usize> {
    let normalized = selector.to_ascii_uppercase();
    let matches = members
        .iter()
        .enumerate()
        .filter(|(_, member)| {
            member.identity.name.eq_ignore_ascii_case(selector)
                || member.identity.fingerprint().starts_with(&normalized)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => bail!("no trusted member matches {selector:?}"),
        _ => bail!("member selector {selector:?} is ambiguous"),
    }
}

fn print_members(state: &TrustedState) {
    for member in &state.members {
        println!(
            "{}  {:?}  {}",
            member.identity.fingerprint(),
            member.role,
            member.identity.name
        );
    }
}

fn member_identity(device: &DeviceIdentity, name: String) -> MemberIdentity {
    MemberIdentity {
        name,
        signing_public_key: device.signing_public_key,
        encryption_public_key: device.encryption_public_key,
        certificate: device.certificate.clone(),
    }
}

fn read_stdin_value(description: &str) -> Result<Zeroizing<String>> {
    ensure!(
        !io::stdin().is_terminal(),
        "refusing to read {description} from an interactive stdin"
    );
    let mut value = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut value)
        .with_context(|| format!("cannot read {description} from stdin"))?;
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    Ok(value)
}

fn print_identity_hint(identity: &dyn IdentitySession, operation: IdentityOperation) {
    if let Some(hint) = identity.interaction_hint(operation) {
        eprintln!("{hint}");
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod integration_tests {
    use std::process::Command as ProcessCommand;

    use tempfile::TempDir;

    use super::*;
    use crate::{backends::test_identity::TestIdentityBackend, identity::IdentityBackend};

    #[test]
    fn trusted_put_and_delete_append_to_custom_git_ref() {
        let directory = TempDir::new().unwrap();
        ProcessCommand::new("git")
            .args(["init", "--quiet"])
            .arg(directory.path())
            .status()
            .unwrap();
        let repository = GitRepository::discover(directory.path()).unwrap();
        let backend = TestIdentityBackend::from_seed(21, "alice");
        let discovered = backend.discovered();
        let device = backend.provision(&discovered).unwrap();
        let mut identity = backend.open(&discovered).unwrap();
        let vault_id = [42; 32];
        let epoch_key = random_epoch_key();
        let public = member_identity(&device, "Alice".into());
        let epoch = MembershipEpoch {
            epoch_number: 1,
            members: vec![EpochMember {
                wrapped_epoch_key: crypto::wrap_epoch_key(&vault_id, 1, &public, &epoch_key)
                    .unwrap(),
                identity: public,
                role: Role::Owner,
            }],
            snapshot: crypto::encrypt_snapshot(&vault_id, 1, &BTreeMap::new(), &epoch_key).unwrap(),
            accepted_proposal: None,
            admission_confirmation: None,
        };
        let genesis = Event::unsigned(
            vault_id,
            [0; 32],
            device.signing_public_key,
            EventPayload::Genesis(epoch),
        )
        .sign(identity.as_mut())
        .unwrap();
        let mut log = EventLog::default();
        log.append(genesis).unwrap();
        let commit_oid = repository
            .append_vault_log("test", None, &log, "create test vault")
            .unwrap();
        let state = derive_trusted_state(&log.events, &DeriveOptions::default()).unwrap();
        repository
            .write_local_checkpoint("test", &state.current_trust_hash)
            .unwrap();
        let mut vault = OpenVault {
            repository: repository.clone(),
            vault_name: "test".into(),
            commit_oid,
            log,
            state,
            values: BTreeMap::new(),
            epoch_key,
            identity,
        };

        vault
            .append_put("TOKEN".into(), VaultValue::Text("secret".into()))
            .unwrap();
        assert_eq!(
            vault.values.get("TOKEN"),
            Some(&VaultValue::Text("secret".into()))
        );
        assert_eq!(
            repository
                .read_vault("test")
                .unwrap()
                .unwrap()
                .log
                .events
                .len(),
            2
        );

        vault.append_delete("TOKEN".into()).unwrap();
        assert!(!vault.values.contains_key("TOKEN"));
        let stored = repository.read_vault("test").unwrap().unwrap();
        assert_eq!(stored.log.events.len(), 3);
        let replayed = derive_trusted_state(
            &stored.log.events,
            &DeriveOptions {
                local_checkpoint: repository.read_local_checkpoint("test").unwrap(),
                ..DeriveOptions::default()
            },
        )
        .unwrap();
        assert!(replayed.unlock_values(&vault.epoch_key).unwrap().is_empty());
    }

    #[test]
    fn opaque_proposal_is_inert_until_owner_admission_epoch() {
        let directory = TempDir::new().unwrap();
        ProcessCommand::new("git")
            .args(["init", "--quiet"])
            .arg(directory.path())
            .status()
            .unwrap();
        let repository = GitRepository::discover(directory.path()).unwrap();
        let alice_backend = TestIdentityBackend::from_seed(31, "alice");
        let alice_discovered = alice_backend.discovered();
        let alice_device = alice_backend.provision(&alice_discovered).unwrap();
        let mut alice = alice_backend.open(&alice_discovered).unwrap();
        let vault_id = [52; 32];
        let epoch_key = random_epoch_key();
        let alice_member = member_identity(&alice_device, "Alice".into());
        let epoch = MembershipEpoch {
            epoch_number: 1,
            members: vec![EpochMember {
                wrapped_epoch_key: crypto::wrap_epoch_key(&vault_id, 1, &alice_member, &epoch_key)
                    .unwrap(),
                identity: alice_member,
                role: Role::Owner,
            }],
            snapshot: crypto::encrypt_snapshot(&vault_id, 1, &BTreeMap::new(), &epoch_key).unwrap(),
            accepted_proposal: None,
            admission_confirmation: None,
        };
        let genesis = Event::unsigned(
            vault_id,
            [0; 32],
            alice_device.signing_public_key,
            EventPayload::Genesis(epoch),
        )
        .sign(alice.as_mut())
        .unwrap();
        let mut log = EventLog::default();
        log.append(genesis).unwrap();
        let commit_oid = repository
            .append_vault_log("onboard", None, &log, "create test vault")
            .unwrap();
        let state = derive_trusted_state(&log.events, &DeriveOptions::default()).unwrap();
        repository
            .write_local_checkpoint("onboard", &state.current_trust_hash)
            .unwrap();
        let mut vault = OpenVault {
            repository: repository.clone(),
            vault_name: "onboard".into(),
            commit_oid,
            log,
            state,
            values: BTreeMap::new(),
            epoch_key,
            identity: alice,
        };
        let (_, phrase) = vault.create_invitation(30, 4).unwrap();
        let invitation = vault
            .state
            .active_invitations
            .values()
            .next()
            .unwrap()
            .clone();

        let bob_backend = TestIdentityBackend::from_seed(32, "bob");
        let bob_discovered = bob_backend.discovered();
        let bob_device = bob_backend.provision(&bob_discovered).unwrap();
        let mut bob = bob_backend.open(&bob_discovered).unwrap();
        let bob_member = member_identity(&bob_device, "Bob".into());
        let (client_state, request) =
            invitation::start_proposal(&invitation, bob_member.clone(), &phrase).unwrap();
        let start = Event::unsigned(
            vault_id,
            vault.state.current_trust_hash,
            bob_device.signing_public_key,
            EventPayload::ProposeUser {
                invitation_id: invitation.invitation_id,
                identity: bob_member.clone(),
                response_event_hash: None,
                pake_message: request,
            },
        )
        .sign(bob.as_mut())
        .unwrap();
        let start_hash = start.event_hash().unwrap();
        let stored = append_candidate(
            &repository,
            "onboard",
            StoredLog {
                commit_oid: vault.commit_oid.clone(),
                log: vault.log.clone(),
            },
            start,
            "start proposal",
        )
        .unwrap();
        vault.commit_oid = stored.commit_oid;
        vault.log = stored.log;
        vault.state = derive_trusted_state(
            &vault.log.events,
            &DeriveOptions {
                now: now_unix(),
                ..DeriveOptions::default()
            },
        )
        .unwrap();
        assert_eq!(vault.state.members.len(), 1);
        let response_hash = vault
            .respond_to_proposal(&hex::encode_upper(start_hash))
            .unwrap();
        let response = vault
            .state
            .invitation_responses
            .get(&response_hash)
            .unwrap()
            .clone();
        let (finalization, client_session_key) = invitation::finish_proposal(
            &vault_id,
            &invitation,
            &start_hash,
            &response,
            client_state,
            &phrase,
        )
        .unwrap();
        let final_event = Event::unsigned(
            vault_id,
            vault.state.current_trust_hash,
            bob_device.signing_public_key,
            EventPayload::ProposeUser {
                invitation_id: invitation.invitation_id,
                identity: bob_member,
                response_event_hash: Some(response_hash),
                pake_message: finalization,
            },
        )
        .sign(bob.as_mut())
        .unwrap();
        let final_hash = final_event.event_hash().unwrap();
        let stored = append_candidate(
            &repository,
            "onboard",
            StoredLog {
                commit_oid: vault.commit_oid.clone(),
                log: vault.log.clone(),
            },
            final_event,
            "finish proposal",
        )
        .unwrap();
        vault.commit_oid = stored.commit_oid;
        vault.log = stored.log;
        vault.state = derive_trusted_state(
            &vault.log.events,
            &DeriveOptions {
                now: now_unix(),
                ..DeriveOptions::default()
            },
        )
        .unwrap();
        assert_eq!(vault.state.members.len(), 1);

        vault
            .approve_proposal(&hex::encode_upper(final_hash))
            .unwrap();
        assert_eq!(vault.state.members.len(), 2);
        assert!(vault
            .state
            .member_for_public_keys(
                &bob_device.signing_public_key,
                &bob_device.encryption_public_key
            )
            .is_some());
        let admission = vault
            .log
            .events
            .iter()
            .find(|event| {
                matches!(
                    &event.payload,
                    EventPayload::MembershipEpoch(epoch)
                        if epoch.accepted_proposal == Some(final_hash)
                )
            })
            .unwrap();
        let EventPayload::MembershipEpoch(epoch) = &admission.payload else {
            unreachable!()
        };
        invitation::verify_admission_confirmation(
            &client_session_key,
            &vault_id,
            &admission.parent_trust_hash,
            epoch,
        )
        .unwrap();
    }
}
