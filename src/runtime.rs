use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::{self, IsTerminal, Read},
    process::{Child, Command as ProcessCommand, ExitStatus, Stdio},
};

use crate::{
    backends,
    cli::{Cli, Command},
    crypto::{self, random_epoch_key, unwrap_epoch_key, DecryptedMutation, VaultValue},
    event::{
        EpochMember, Event, EventLog, EventPayload, MemberIdentity, MembershipEpoch, Role,
        MAX_NAME_LEN,
    },
    git::{self, GitRepository, StoredLog},
    identity::{
        self, DeviceIdentity, DiscoveredIdentity, IdentityOperation, IdentitySession, IdentityState,
    },
    manager::{self, ManagerAction},
    state::{derive_trusted_state, DeriveOptions, TrustedState},
    terminal::{
        choose_identity, discard_pending_input, discover_identities, event_to_input, prompt_line,
        require_terminal, suspend_terminal, with_terminal,
    },
    tui::{Effect, VaultUi},
};
use anyhow::{bail, ensure, Context, Result};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub enum RunOutcome {
    Success,
    Child(ExitStatus),
}

impl RunOutcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Child(status) => child_exit_code(status),
        }
    }
}

pub fn run(cli: Cli) -> Result<RunOutcome> {
    let exec_mappings = match &cli.command {
        Some(Command::Exec { environment, .. }) => Some(parse_environment_mappings(environment)?),
        _ => None,
    };
    let repository = GitRepository::discover(".")?;
    let Some(vault) = cli.vault.clone() else {
        ensure!(
            cli.command.is_none(),
            "a vault name is required when using a vault command"
        );
        return match manager::run(&repository)? {
            Some(ManagerAction::Open(vault)) => {
                let stored = repository
                    .read_vault(&vault)?
                    .with_context(|| format!("vault {vault:?} no longer exists"))?;
                run_interactive_existing(&repository, &vault, stored, cli.identity.as_deref())?;
                Ok(RunOutcome::Success)
            }
            Some(ManagerAction::Create(vault)) => {
                ensure!(
                    repository.read_vault(&vault)?.is_none(),
                    "vault {vault:?} already exists"
                );
                create_vault(&repository, &vault, cli.identity.as_deref())?.run_tui()?;
                Ok(RunOutcome::Success)
            }
            None => Ok(RunOutcome::Success),
        };
    };
    git::validate_vault_name(&vault)?;

    if let Some(Command::Fetch { remote }) = &cli.command {
        fetch_and_advance(&repository, &vault, remote)?;
        return Ok(RunOutcome::Success);
    }
    if let Some(Command::Push { remote }) = &cli.command {
        repository.push_vault(remote, &vault)?;
        println!("Pushed refs/vaults/{vault} to {remote}");
        return Ok(RunOutcome::Success);
    }

    let stored = repository.read_vault(&vault)?;
    if matches!(cli.command, Some(Command::Verify)) {
        let stored = stored.with_context(|| format!("vault {vault:?} does not exist"))?;
        let state = derive_with_checkpoints(&repository, &vault, &stored.log, None)?;
        print_verification(&stored, &state);
        return Ok(RunOutcome::Success);
    }
    if cli.command.is_none() {
        if let Some(stored) = stored.clone() {
            run_interactive_existing(&repository, &vault, stored, cli.identity.as_deref())?;
            return Ok(RunOutcome::Success);
        }
    }

    let mut session = match stored {
        Some(stored) => unlock_vault(&repository, &vault, stored, cli.identity.as_deref())?,
        None => {
            ensure!(
                !matches!(&cli.command, Some(Command::Members | Command::Exec { .. })),
                "vault {vault:?} does not exist"
            );
            create_vault(&repository, &vault, cli.identity.as_deref())?
        }
    };
    match cli.command {
        Some(Command::List) => {
            for key in session.values.keys() {
                println!("{key}");
            }
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
        }
        Some(Command::Set { key, r#type, stdin }) => {
            session.require_recovery()?;
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
        }
        Some(Command::Delete { key }) => {
            ensure!(
                session.values.contains_key(&key),
                "secret {key:?} does not exist"
            );
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.append_delete(key)?;
        }
        Some(Command::Members) => print_members(&session.state),
        Some(Command::Exec { child, .. }) => {
            let status = session.exec_child(
                exec_mappings
                    .as_deref()
                    .expect("exec mappings were parsed before unlock"),
                &child,
            )?;
            return Ok(RunOutcome::Child(status));
        }
        Some(Command::AcknowledgeUnrecoverable) => session.acknowledge_unrecoverable()?,
        Some(Command::AddMember {
            name,
            new_identity,
            capability,
        }) => {
            session.add_connected_member(new_identity.as_deref(), name, capability.into())?;
            println!("Member added and checkpointed");
        }
        Some(Command::RotateIdentity { name, new_identity }) => {
            session.rotate_connected_identity(new_identity.as_deref(), name)?;
            println!("Replacement identity commissioned, recovery-tested, and activated");
        }
        Some(Command::RemoveMember { member }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.remove_member(&member)?;
        }
        Some(Command::SetRole { member, role }) => {
            print_identity_hint(session.identity.as_ref(), IdentityOperation::Sign);
            session.set_role(&member, role.into())?;
        }
        Some(Command::Verify | Command::Fetch { .. } | Command::Push { .. }) => unreachable!(),
        None => session.run_tui()?,
    }
    Ok(RunOutcome::Success)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EnvironmentMapping {
    destination: String,
    vault_key: String,
}

fn parse_environment_mappings(specifications: &[String]) -> Result<Vec<EnvironmentMapping>> {
    ensure!(
        !specifications.is_empty(),
        "exec requires at least one --env mapping"
    );
    let mut destinations = BTreeSet::new();
    let mut mappings = Vec::with_capacity(specifications.len());
    for specification in specifications {
        ensure!(
            specification.matches('=').count() <= 1,
            "malformed environment mapping {specification:?}"
        );
        let (destination, vault_key) = specification
            .split_once('=')
            .unwrap_or((specification.as_str(), specification.as_str()));
        ensure!(
            is_environment_name(destination),
            "invalid environment variable name {destination:?}"
        );
        ensure!(
            !vault_key.is_empty() && !vault_key.contains('\0'),
            "environment mapping {specification:?} has an empty or invalid vault key"
        );
        ensure!(
            destinations.insert(destination.to_owned()),
            "duplicate destination environment variable {destination:?}"
        );
        mappings.push(EnvironmentMapping {
            destination: destination.to_owned(),
            vault_key: vault_key.to_owned(),
        });
    }
    Ok(mappings)
}

fn is_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

struct InjectedEnvironment {
    destination: String,
    value: Zeroizing<String>,
}

fn resolve_environment(
    values: &BTreeMap<String, VaultValue>,
    mappings: &[EnvironmentMapping],
) -> Result<Vec<InjectedEnvironment>> {
    let mut injected = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let value = values
            .get(&mapping.vault_key)
            .with_context(|| format!("secret {:?} does not exist", mapping.vault_key))?;
        let value = Zeroizing::new(value.display());
        ensure!(
            !value.contains('\0'),
            "secret {:?} contains an embedded NUL and cannot be represented in a process environment",
            mapping.vault_key
        );
        injected.push(InjectedEnvironment {
            destination: mapping.destination.clone(),
            value,
        });
    }
    Ok(injected)
}

#[cfg(test)]
fn spawn_child_with_environment(
    values: &BTreeMap<String, VaultValue>,
    mappings: &[EnvironmentMapping],
    child: &[OsString],
) -> Result<Child> {
    let injected = resolve_environment(values, mappings)?;
    spawn_child(&injected, child)
}

fn spawn_child(injected: &[InjectedEnvironment], child: &[OsString]) -> Result<Child> {
    ensure!(
        !child.is_empty(),
        "exec requires a child program after `--`"
    );
    let mut command = ProcessCommand::new(&child[0]);
    command
        .args(&child[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for variable in injected {
        command.env(&variable.destination, variable.value.as_str());
    }
    command.spawn().context("cannot spawn child process")
}

fn child_exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(1, |signal| 128 + signal)
    }
    #[cfg(not(unix))]
    {
        1
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
    fn exec_child(
        mut self,
        mappings: &[EnvironmentMapping],
        child: &[OsString],
    ) -> Result<ExitStatus> {
        let injected = resolve_environment(&self.values, mappings)?;
        // Snapshot replay necessarily reconstructs the vault, but only requested values need to
        // remain once resolution succeeds. Drop all originals and the epoch key before spawn.
        self.values.clear();
        self.epoch_key.zeroize();
        let mut process = spawn_child(&injected, child)?;
        // After spawn, the receiving process/OS owns its copies. Drop our selected copies and
        // remaining vault/session state before waiting for the child's full lifetime.
        drop(injected);
        drop(self);
        process.wait().context("cannot wait for child process")
    }

    fn recovery_ready(&self) -> Result<bool> {
        Ok(self
            .state
            .members
            .iter()
            .filter(|member| member.role == Role::Owner)
            .count()
            >= 2
            || self
                .repository
                .has_unrecoverable_ack(&self.vault_name, &self.state.vault_id)?)
    }

    fn require_recovery(&self) -> Result<()> {
        ensure!(
            self.recovery_ready()?,
            "recovery is not configured: commission and test a second owner, or run `git vault {} acknowledge-unrecoverable`",
            self.vault_name
        );
        Ok(())
    }

    fn acknowledge_unrecoverable(&self) -> Result<()> {
        require_terminal()?;
        ensure!(
            self.state
                .members
                .iter()
                .filter(|member| member.role == Role::Owner)
                .count()
                < 2,
            "the vault already has a tested second owner recovery identity"
        );
        let expected = format!("UNRECOVERABLE {}", self.vault_name);
        eprintln!(
            "WARNING: without another owner identity, loss or failure of this identity permanently loses every secret in the vault."
        );
        let confirmation = prompt_line(&format!("Type {expected:?} to accept this risk: "))?;
        ensure!(
            confirmation == expected,
            "unrecoverable acknowledgement cancelled"
        );
        self.repository
            .write_unrecoverable_ack(&self.vault_name, &self.state.vault_id)?;
        println!("Recorded local unrecoverable-use acknowledgement");
        Ok(())
    }

    fn append_put(&mut self, key: String, value: VaultValue) -> Result<()> {
        self.require_recovery()?;
        let previous_mutation_count = self.state.trusted_event_hashes.len();
        let (nonce, ciphertext) = crypto::encrypt_mutation(
            &self.state.vault_id,
            self.state.membership_epoch,
            &DecryptedMutation::Put {
                key: key.clone(),
                value: value.clone(),
            },
            &self.epoch_key,
        )?;
        let result = self.append_payload(
            EventPayload::Mutation {
                epoch_number: self.state.membership_epoch,
                parents: self.state.mutation_heads.clone(),
                nonce,
                ciphertext,
            },
            "append encrypted Put mutation",
        );
        if self.state.trusted_event_hashes.len() > previous_mutation_count {
            self.values.insert(key, value);
        }
        result
    }

    fn append_delete(&mut self, key: String) -> Result<()> {
        self.require_recovery()?;
        let previous_mutation_count = self.state.trusted_event_hashes.len();
        let (nonce, ciphertext) = crypto::encrypt_mutation(
            &self.state.vault_id,
            self.state.membership_epoch,
            &DecryptedMutation::Delete { key: key.clone() },
            &self.epoch_key,
        )?;
        let result = self.append_payload(
            EventPayload::Mutation {
                epoch_number: self.state.membership_epoch,
                parents: self.state.mutation_heads.clone(),
                nonce,
                ciphertext,
            },
            "append encrypted Delete mutation",
        );
        if self.state.trusted_event_hashes.len() > previous_mutation_count {
            self.values.remove(&key);
        }
        result
    }

    fn add_connected_member(
        &mut self,
        requested_identity: Option<&str>,
        name: String,
        role: Role,
    ) -> Result<()> {
        let name = name.trim();
        ensure!(!name.is_empty(), "member name cannot be empty");
        ensure!(name.len() <= MAX_NAME_LEN, "member name is too long");
        ensure!(!name.contains('\0'), "member name contains a NUL byte");
        ensure!(
            self.state
                .member_for_signing_key(&self.identity.identity().signing_public_key)
                .is_some_and(|member| member.role == Role::Owner),
            "only an owner can add members"
        );
        let candidates = discover_identities()?
            .into_iter()
            .filter(|candidate| match &candidate.state {
                IdentityState::Ready(device) => self
                    .state
                    .member_for_public_keys(
                        &device.signing_public_key,
                        &device.encryption_public_key,
                    )
                    .is_none(),
                IdentityState::Provisionable => true,
                IdentityState::Unavailable(_) => false,
            })
            .collect();
        let selected = choose_identity(
            candidates,
            requested_identity,
            true,
            false,
            "Select the physically connected identity to add",
        )?;
        let device = backends::provision(&selected)?;
        let ready = DiscoveredIdentity {
            backend: device.backend,
            locator: device.locator.clone(),
            display_name: device.display_name.clone(),
            detail: format!("identity {}", device.fingerprint()),
            state: IdentityState::Ready(device.clone()),
        };
        let mut new_session = backends::open(&ready)?;
        self.add_member(
            member_identity(&device, name.to_owned()),
            role,
            new_session.as_mut(),
        )
    }

    fn rotate_connected_identity(
        &mut self,
        requested_identity: Option<&str>,
        name: String,
    ) -> Result<()> {
        let name = name.trim();
        ensure!(!name.is_empty(), "replacement member name cannot be empty");
        ensure!(
            name.len() <= MAX_NAME_LEN,
            "replacement member name is too long"
        );
        ensure!(
            !name.contains('\0'),
            "replacement member name contains a NUL byte"
        );
        let old_signing_key = self.identity.identity().signing_public_key;
        ensure!(
            self.state
                .member_for_signing_key(&old_signing_key)
                .is_some_and(|member| member.role == Role::Owner),
            "only an owner identity can be rotated"
        );

        let candidates = discover_identities()?
            .into_iter()
            .filter(|candidate| match &candidate.state {
                IdentityState::Ready(device) => device.signing_public_key != old_signing_key,
                IdentityState::Provisionable => true,
                IdentityState::Unavailable(_) => false,
            })
            .collect();
        let selected = choose_identity(
            candidates,
            requested_identity,
            true,
            false,
            "Select the physically connected replacement identity",
        )?;
        let device = backends::provision(&selected)?;
        ensure!(
            device.signing_public_key != old_signing_key
                && device.encryption_public_key != self.identity.identity().encryption_public_key,
            "replacement must be a distinct identity"
        );
        let ready = DiscoveredIdentity {
            backend: device.backend,
            locator: device.locator.clone(),
            display_name: device.display_name.clone(),
            detail: format!("identity {}", device.fingerprint()),
            state: IdentityState::Ready(device.clone()),
        };
        let mut replacement = backends::open(&ready)?;
        let proposed = member_identity(&device, name.to_owned());

        match self.state.member_for_public_keys(
            &proposed.signing_public_key,
            &proposed.encryption_public_key,
        ) {
            None => self.add_member(proposed.clone(), Role::Owner, replacement.as_mut())?,
            Some(member) => ensure!(
                member.role == Role::Owner,
                "existing replacement identity is not an owner"
            ),
        }

        if self
            .state
            .member_for_signing_key(&old_signing_key)
            .is_none()
        {
            return Ok(());
        }
        self.finish_identity_rotation(old_signing_key, &proposed, replacement.as_mut())
    }

    fn finish_identity_rotation(
        &mut self,
        old_signing_key: [u8; 32],
        replacement: &MemberIdentity,
        replacement_session: &mut dyn IdentitySession,
    ) -> Result<()> {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        print_identity_hint(replacement_session, IdentityOperation::Sign);
        let signature = replacement_session.sign(&challenge)?;
        ed25519_dalek::VerifyingKey::from_bytes(&replacement.signing_public_key)?
            .verify_strict(
                &challenge,
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .context("replacement identity failed signing proof")?;

        let epoch_number = self.state.membership_epoch + 1;
        let next_epoch_key = random_epoch_key();
        let members = self
            .state
            .members
            .iter()
            .filter(|member| member.identity.signing_public_key != old_signing_key)
            .map(|member| {
                Ok(EpochMember {
                    wrapped_epoch_key: crypto::wrap_epoch_key(
                        &self.state.vault_id,
                        epoch_number,
                        &member.identity,
                        &next_epoch_key,
                    )?,
                    identity: member.identity.clone(),
                    role: member.role,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            members.iter().any(|member| {
                member.role == Role::Owner
                    && member.identity.signing_public_key == replacement.signing_public_key
                    && member.identity.encryption_public_key == replacement.encryption_public_key
            }),
            "replacement owner is absent from the rotated membership"
        );
        let replacement_member = members
            .iter()
            .find(|member| {
                member.identity.signing_public_key == replacement.signing_public_key
                    && member.identity.encryption_public_key == replacement.encryption_public_key
            })
            .context("replacement identity is absent")?;
        print_identity_hint(replacement_session, IdentityOperation::Agree);
        let proof = unwrap_epoch_key(
            &self.state.vault_id,
            epoch_number,
            &replacement_member.identity,
            &replacement_member.wrapped_epoch_key,
            replacement_session,
        )?;
        ensure!(
            *proof == *next_epoch_key,
            "replacement failed encryption proof"
        );
        let snapshot = crypto::encrypt_snapshot(
            &self.state.vault_id,
            epoch_number,
            &self.values,
            &next_epoch_key,
        )?;
        ensure!(
            crypto::decrypt_snapshot(&self.state.vault_id, epoch_number, &snapshot, &proof,)?
                == self.values,
            "replacement failed snapshot recovery drill"
        );
        let epoch = MembershipEpoch {
            epoch_number,
            members,
            snapshot,
            previous_epoch_heads: self.state.mutation_heads.clone(),
        };
        print_identity_hint(self.identity.as_ref(), IdentityOperation::Sign);
        let local_checkpoint = self.append_payload(
            EventPayload::MembershipEpoch(epoch),
            "activate replacement identity",
        );
        if self.state.membership_epoch != epoch_number {
            return local_checkpoint;
        }
        self.epoch_key = next_epoch_key;
        let old_checkpoint =
            advance_identity_checkpoint(self.identity.as_mut(), &self.state, &self.vault_name);
        let replacement_checkpoint =
            advance_identity_checkpoint(replacement_session, &self.state, &self.vault_name);
        match (local_checkpoint, old_checkpoint, replacement_checkpoint) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (local, old, replacement) => anyhow::bail!(
                "rotation committed, but checkpointing is incomplete (local: {}; old: {}; replacement: {}). Reconnect affected identities and reopen the vault",
                local.map_or_else(|error| format!("{error:#}"), |_| "ok".into()),
                old.map_or_else(|error| format!("{error:#}"), |_| "ok".into()),
                replacement.map_or_else(|error| format!("{error:#}"), |_| "ok".into()),
            ),
        }
    }

    fn add_member(
        &mut self,
        proposed: MemberIdentity,
        role: Role,
        new_session: &mut dyn IdentitySession,
    ) -> Result<()> {
        ensure!(
            self.state.members.iter().all(|member| {
                member.identity.signing_public_key != proposed.signing_public_key
                    && member.identity.encryption_public_key != proposed.encryption_public_key
            }),
            "identity is already a trusted member or reuses a trusted key"
        );

        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        print_identity_hint(new_session, IdentityOperation::Sign);
        let signature = new_session.sign(&challenge)?;
        ed25519_dalek::VerifyingKey::from_bytes(&proposed.signing_public_key)?
            .verify_strict(
                &challenge,
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .context("new identity failed signing proof")?;

        let epoch_number = self.state.membership_epoch + 1;
        let next_epoch_key = random_epoch_key();
        let mut members = self.state.members.clone();
        let added = EpochMember {
            wrapped_epoch_key: crypto::wrap_epoch_key(
                &self.state.vault_id,
                epoch_number,
                &proposed,
                &next_epoch_key,
            )?,
            identity: proposed,
            role,
        };
        print_identity_hint(new_session, IdentityOperation::Agree);
        let proof = unwrap_epoch_key(
            &self.state.vault_id,
            epoch_number,
            &added.identity,
            &added.wrapped_epoch_key,
            new_session,
        )?;
        ensure!(
            *proof == *next_epoch_key,
            "new identity failed encryption proof"
        );
        members.push(added);
        let snapshot = crypto::encrypt_snapshot(
            &self.state.vault_id,
            epoch_number,
            &self.values,
            &next_epoch_key,
        )?;
        ensure!(
            crypto::decrypt_snapshot(&self.state.vault_id, epoch_number, &snapshot, &proof,)?
                == self.values,
            "new identity failed snapshot recovery drill"
        );
        let epoch = MembershipEpoch {
            epoch_number,
            members,
            snapshot,
            previous_epoch_heads: self.state.mutation_heads.clone(),
        };
        print_identity_hint(self.identity.as_ref(), IdentityOperation::Sign);
        let local_checkpoint =
            self.append_payload(EventPayload::MembershipEpoch(epoch), "add connected member");
        if self.state.membership_epoch != epoch_number {
            return local_checkpoint;
        }
        self.epoch_key = next_epoch_key;

        let owner_checkpoint =
            advance_identity_checkpoint(self.identity.as_mut(), &self.state, &self.vault_name);
        let member_checkpoint =
            advance_identity_checkpoint(new_session, &self.state, &self.vault_name);
        match (local_checkpoint, owner_checkpoint, member_checkpoint) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (local, owner, member) => anyhow::bail!(
                "member was admitted, but checkpointing is incomplete (local: {}; owner: {}; new member: {}). Reconnect each affected key and reopen the vault to retry",
                local.map_or_else(|error| format!("{error:#}"), |_| "ok".into()),
                owner.map_or_else(|error| format!("{error:#}"), |_| "ok".into()),
                member.map_or_else(|error| format!("{error:#}"), |_| "ok".into()),
            ),
        }
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
            previous_epoch_heads: self.state.mutation_heads.clone(),
        };
        let result = self.append_payload(EventPayload::MembershipEpoch(epoch), message);
        if self.state.membership_epoch == epoch_number {
            self.epoch_key = next_epoch_key;
        }
        result?;
        advance_identity_checkpoint(self.identity.as_mut(), &self.state, &self.vault_name)
            .context("membership changed, but the hardware checkpoint was not advanced")?;
        Ok(())
    }

    fn append_payload(&mut self, payload: EventPayload, message: &str) -> Result<()> {
        ensure!(
            self.state.fork.is_none(),
            "cannot append while a trusted fork is unresolved"
        );
        let member = self
            .state
            .member_for_signing_key(&self.identity.identity().signing_public_key)
            .context("the selected identity is not a trusted member")?;
        let requires_owner = !matches!(&payload, EventPayload::Mutation { .. });
        ensure!(
            !requires_owner || member.role == Role::Owner,
            "only an owner can manage membership"
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
                local_checkpoint: Some(self.state.trusted_event_hashes.clone()),
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
        self.log = next_log;
        self.commit_oid = next_commit;
        self.state = next_state;
        self.repository
            .write_local_checkpoint(&self.vault_name, &self.state.trusted_event_hashes)
            .context("event committed, but the local freshness checkpoint was not advanced")
    }

    fn run_tui(&mut self) -> Result<()> {
        require_terminal()?;
        let mut app = VaultUi::new(self.values.clone(), self.state.members.clone());
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
                    | Effect::AddMember { .. }
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
                    Err(error) => app.set_status(format!("Put failed: {error:#}")),
                },
                Effect::Delete { key } => match self.append_delete(key.clone()) {
                    Ok(()) => app.apply_delete(&key),
                    Err(error) => app.set_status(format!("Delete failed: {error:#}")),
                },
                Effect::RemoveMember { signing_public_key } => {
                    let previous_epoch = self.state.membership_epoch;
                    match suspend_terminal(terminal, || {
                        self.remove_member_by_signing_key(&signing_public_key)
                    }) {
                        Ok(()) => {
                            refresh_access_view(&mut app, &self.state);
                            app.set_status("Member removed; epoch key rotated");
                        }
                        Err(error) if self.state.membership_epoch > previous_epoch => {
                            refresh_access_view(&mut app, &self.state);
                            app.set_status(format!(
                                "DEGRADED SECURITY: membership changed but hardware checkpoint failed: {error:#}"
                            ));
                        }
                        Err(error) => {
                            app.set_status(format!("Member not removed: {error:#}"));
                        }
                    }
                }
                Effect::AddMember { role } => {
                    let previous_epoch = self.state.membership_epoch;
                    let result = suspend_terminal(terminal, || {
                        let name = prompt_line("New member name: ")?;
                        self.add_connected_member(None, name, role)
                    });
                    refresh_access_view(&mut app, &self.state);
                    match result {
                        Ok(()) => {
                            app.set_status("Member added; epoch rotated and keys checkpointed")
                        }
                        Err(error) if self.state.membership_epoch > previous_epoch => app
                            .set_status(format!("Member admitted; checkpoint pending: {error:#}")),
                        Err(error) => app.set_status(format!("Member not added: {error:#}")),
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
    let device = backends::provision(&selected)?;
    let ready = DiscoveredIdentity {
        backend: device.backend,
        locator: device.locator.clone(),
        display_name: device.display_name.clone(),
        detail: format!("identity {}", device.fingerprint()),
        state: IdentityState::Ready(device.clone()),
    };
    let mut session = backends::open(&ready)?;
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
        previous_epoch_heads: Vec::new(),
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
    repository.write_local_checkpoint(vault_name, &state.trusted_event_hashes)?;
    advance_identity_checkpoint(session.as_mut(), &state, vault_name)
        .context("vault was created, but its YubiKey checkpoint was not persisted")?;
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
    unlock_vault(repository, vault_name, stored, requested_identity)?.run_tui()
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
                    .map(|member| format!("trusted {}", capability_name(member.role)))
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
    let mut identity = backends::open(&selected)?;
    let hardware_checkpoint = identity.read_trust_record(vault_name)?;
    let state = derive_with_checkpoints(
        repository,
        vault_name,
        &stored.log,
        hardware_checkpoint.clone(),
    )?;
    if hardware_checkpoint
        .as_ref()
        .is_none_or(|checkpoint| checkpoint.membership_epoch < state.membership_epoch)
    {
        advance_identity_checkpoint(identity.as_mut(), &state, vault_name).context(
            "verified a newer membership epoch, but could not advance the YubiKey checkpoint",
        )?;
    }
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
    repository.write_local_checkpoint(vault_name, &state.trusted_event_hashes)?;
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

fn advance_identity_checkpoint(
    identity: &mut dyn IdentitySession,
    state: &TrustedState,
    vault_name: &str,
) -> Result<()> {
    let desired = state.trusted_checkpoint(vault_name);
    if let Some(existing) = identity.read_trust_record(vault_name)? {
        ensure!(
            existing.membership_epoch <= desired.membership_epoch,
            "hardware checkpoint is newer than the verified membership epoch"
        );
        if existing == desired {
            return Ok(());
        }
    }
    identity.write_trust_record(&desired)
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
            hardware_checkpoint,
            local_checkpoint,
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
    let local_log = current
        .as_ref()
        .map(|stored| stored.log.clone())
        .unwrap_or_default();
    let merged_log = local_log.union(&remote_log.log)?;
    let state = derive_with_checkpoints(repository, vault, &merged_log, None)?;
    ensure!(
        state.fork.is_none(),
        "merged vault event collection contains an unresolved trusted fork"
    );
    repository.write_merged_vault_log(
        vault,
        current.as_ref().map(|stored| stored.commit_oid.as_str()),
        &remote_log.commit_oid,
        &merged_log,
        "merge fetched vault event set",
    )?;
    repository.write_local_checkpoint(vault, &state.trusted_event_hashes)?;
    println!(
        "Merged {} verified events into refs/vaults/{vault}; trusted hash {}",
        merged_log.events.len(),
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
    println!("trusted events     {}", state.trusted_event_hashes.len());
    println!("raw valid events   {}", stored.log.events.len());
    println!("invalid records    {}", stored.log.diagnostics.len());
    println!(
        "fork               {}",
        if state.fork.is_some() { "yes" } else { "no" }
    );
    for diagnostic in stored.log.diagnostics.iter().chain(&state.diagnostics) {
        println!("diagnostic         {diagnostic}");
    }
}

fn refresh_access_view(app: &mut VaultUi, state: &TrustedState) {
    app.refresh_access(state.members.clone());
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

fn capability_name(role: Role) -> &'static str {
    match role {
        Role::Member => "member: read/write",
        Role::Owner => "owner: read/write + access management",
    }
}

fn print_members(state: &TrustedState) {
    for member in &state.members {
        println!(
            "{}  {}  {}",
            member.identity.fingerprint(),
            capability_name(member.role),
            member.identity.name
        );
    }
}

fn member_identity(device: &DeviceIdentity, name: String) -> MemberIdentity {
    MemberIdentity {
        name,
        signing_public_key: device.signing_public_key,
        encryption_public_key: device.encryption_public_key,
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

#[cfg(test)]
mod integration_tests {
    use std::{
        env, fs,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use tempfile::TempDir;

    use super::*;
    use crate::backends::test_identity::TestIdentityBackend;

    struct FailCheckpointOnce {
        inner: Box<dyn IdentitySession>,
        fail: bool,
    }

    struct CountSigning {
        inner: Box<dyn IdentitySession>,
        count: Arc<AtomicUsize>,
    }

    impl IdentitySession for CountSigning {
        fn identity(&self) -> &DeviceIdentity {
            self.inner.identity()
        }

        fn sign(&mut self, message: &[u8; 32]) -> Result<[u8; 64]> {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.inner.sign(message)
        }

        fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
            self.inner.agree(peer_public_key)
        }

        fn read_trust_record(
            &mut self,
            vault_name: &str,
        ) -> Result<Option<identity::VaultTrustRecord>> {
            self.inner.read_trust_record(vault_name)
        }

        fn write_trust_record(&mut self, record: &identity::VaultTrustRecord) -> Result<()> {
            self.inner.write_trust_record(record)
        }
    }

    impl IdentitySession for FailCheckpointOnce {
        fn identity(&self) -> &DeviceIdentity {
            self.inner.identity()
        }

        fn sign(&mut self, message: &[u8; 32]) -> Result<[u8; 64]> {
            self.inner.sign(message)
        }

        fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
            self.inner.agree(peer_public_key)
        }

        fn read_trust_record(
            &mut self,
            vault_name: &str,
        ) -> Result<Option<identity::VaultTrustRecord>> {
            self.inner.read_trust_record(vault_name)
        }

        fn write_trust_record(&mut self, record: &identity::VaultTrustRecord) -> Result<()> {
            if self.fail {
                self.fail = false;
                anyhow::bail!("simulated interrupted checkpoint write");
            }
            self.inner.write_trust_record(record)
        }
    }

    fn open_test_vault(
        values: BTreeMap<String, VaultValue>,
    ) -> (OpenVault, GitRepository, Arc<AtomicUsize>, TempDir) {
        let directory = TempDir::new().unwrap();
        ProcessCommand::new("git")
            .args(["init", "--quiet"])
            .arg(directory.path())
            .status()
            .unwrap();
        let repository = GitRepository::discover(directory.path()).unwrap();
        let backend = TestIdentityBackend::from_seed(81, "exec-reader");
        let device = backend.device();
        let mut signing_identity = backend.open();
        let vault_id = [82; 32];
        let epoch_key = random_epoch_key();
        let public = member_identity(&device, "Exec reader".into());
        let epoch = MembershipEpoch {
            epoch_number: 1,
            members: vec![EpochMember {
                wrapped_epoch_key: crypto::wrap_epoch_key(&vault_id, 1, &public, &epoch_key)
                    .unwrap(),
                identity: public,
                role: Role::Owner,
            }],
            snapshot: crypto::encrypt_snapshot(&vault_id, 1, &values, &epoch_key).unwrap(),
            previous_epoch_heads: Vec::new(),
        };
        let genesis = Event::unsigned(
            vault_id,
            [0; 32],
            device.signing_public_key,
            EventPayload::Genesis(epoch),
        )
        .sign(signing_identity.as_mut())
        .unwrap();
        let mut log = EventLog::default();
        log.append(genesis).unwrap();
        let commit_oid = repository
            .append_vault_log("exec-test", None, &log, "create exec test vault")
            .unwrap();
        let state = derive_trusted_state(&log.events, &DeriveOptions::default()).unwrap();
        repository
            .write_local_checkpoint("exec-test", &state.trusted_event_hashes)
            .unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let identity = Box::new(CountSigning {
            inner: backend.open(),
            count: Arc::clone(&count),
        });
        (
            OpenVault {
                repository: repository.clone(),
                vault_name: "exec-test".into(),
                commit_oid,
                log,
                state,
                values,
                epoch_key,
                identity,
            },
            repository,
            count,
            directory,
        )
    }

    fn write_executable(path: &std::path::Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn environment_mappings_are_strict_and_destinations_are_unique() {
        let mappings =
            parse_environment_mappings(&["TOKEN".into(), "API_TOKEN=INTERNAL_TOKEN".into()])
                .unwrap();
        assert_eq!(
            mappings,
            [
                EnvironmentMapping {
                    destination: "TOKEN".into(),
                    vault_key: "TOKEN".into(),
                },
                EnvironmentMapping {
                    destination: "API_TOKEN".into(),
                    vault_key: "INTERNAL_TOKEN".into(),
                },
            ]
        );

        for malformed in [
            "",
            "=TOKEN",
            "9TOKEN=TOKEN",
            "BAD-NAME=TOKEN",
            "TOKEN=",
            "TOKEN=A=B",
        ] {
            assert!(
                parse_environment_mappings(&[malformed.into()]).is_err(),
                "accepted malformed mapping {malformed:?}"
            );
        }
        assert!(parse_environment_mappings(&["TOKEN=A".into(), "TOKEN=B".into()]).is_err());
        assert!(parse_environment_mappings(&[]).is_err());
    }

    #[test]
    fn typed_values_use_the_public_string_representation() {
        let values = BTreeMap::from([
            (
                "TEXT".into(),
                VaultValue::Text("exact text\nline two".into()),
            ),
            ("NUMBER".into(), VaultValue::Number("001.230".into())),
            ("TRUE".into(), VaultValue::Boolean(true)),
            ("FALSE".into(), VaultValue::Boolean(false)),
            ("BYTES".into(), VaultValue::Bytes(vec![0, 0xab, 0xcd, 0xef])),
        ]);
        let mappings = parse_environment_mappings(&[
            "OUT_TEXT=TEXT".into(),
            "OUT_NUMBER=NUMBER".into(),
            "OUT_TRUE=TRUE".into(),
            "OUT_FALSE=FALSE".into(),
            "OUT_BYTES=BYTES".into(),
        ])
        .unwrap();
        let resolved = resolve_environment(&values, &mappings).unwrap();
        let rendered = resolved
            .iter()
            .map(|item| (item.destination.as_str(), item.value.as_str()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(rendered["OUT_TEXT"], "exact text\nline two");
        assert_eq!(rendered["OUT_NUMBER"], "001.230");
        assert_eq!(rendered["OUT_TRUE"], "true");
        assert_eq!(rendered["OUT_FALSE"], "false");
        assert_eq!(rendered["OUT_BYTES"], "00abcdef");
    }

    #[test]
    fn child_receives_mapped_values_inherited_environment_and_literal_arguments() {
        let directory = TempDir::new().unwrap();
        let script = directory.path().join("inspect-environment");
        let output = directory.path().join("received");
        write_executable(
            &script,
            "#!/bin/sh\nset -eu\nprintf '%s\\0' \"$NIT_TEXT\" \"$NIT_NUMBER\" \"$NIT_TRUE\" \"$NIT_FALSE\" \"$NIT_BYTES\" \"$NIT_OVERRIDE\" \"$NIT_INHERITED\" \"$2\" \"$3\" \"$4\" > \"$1\"\nprintf 'child stdout inherited\\n'\nprintf 'child stderr inherited\\n' >&2\n",
        );
        env::set_var("NIT_OVERRIDE", "parent value");
        env::set_var("NIT_INHERITED", "inherited value");
        let values = BTreeMap::from([
            (
                "TEXT_SECRET".into(),
                VaultValue::Text("exact text\nline two".into()),
            ),
            ("NUMBER_SECRET".into(), VaultValue::Number("001.230".into())),
            ("TRUE_SECRET".into(), VaultValue::Boolean(true)),
            ("FALSE_SECRET".into(), VaultValue::Boolean(false)),
            (
                "BYTES_SECRET".into(),
                VaultValue::Bytes(vec![0, 0xab, 0xcd, 0xef]),
            ),
            (
                "OVERRIDE_SECRET".into(),
                VaultValue::Text("vault value".into()),
            ),
        ]);
        let mappings = parse_environment_mappings(&[
            "NIT_TEXT=TEXT_SECRET".into(),
            "NIT_NUMBER=NUMBER_SECRET".into(),
            "NIT_TRUE=TRUE_SECRET".into(),
            "NIT_FALSE=FALSE_SECRET".into(),
            "NIT_BYTES=BYTES_SECRET".into(),
            "NIT_OVERRIDE=OVERRIDE_SECRET".into(),
        ])
        .unwrap();
        let child = [
            script.into_os_string(),
            output.clone().into_os_string(),
            OsString::from("$NOT_EXPANDED"),
            OsString::from("*.txt"),
            OsString::from("semi;colon"),
        ];
        let status = spawn_child_with_environment(&values, &mappings, &child)
            .unwrap()
            .wait()
            .unwrap();
        env::remove_var("NIT_OVERRIDE");
        env::remove_var("NIT_INHERITED");
        assert!(status.success());
        let received = fs::read(output).unwrap();
        let fields = received
            .split(|byte| *byte == 0)
            .take(10)
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            [
                b"exact text\nline two".as_slice(),
                b"001.230",
                b"true",
                b"false",
                b"00abcdef",
                b"vault value",
                b"inherited value",
                b"$NOT_EXPANDED",
                b"*.txt",
                b"semi;colon",
            ]
        );
    }

    #[test]
    fn missing_or_unrepresentable_secret_prevents_child_start() {
        let directory = TempDir::new().unwrap();
        let marker = directory.path().join("started");
        let script = directory.path().join("mark-started");
        write_executable(&script, "#!/bin/sh\ntouch \"$1\"\n");
        let child = [script.into_os_string(), marker.clone().into_os_string()];

        let missing = parse_environment_mappings(&["TOKEN=MISSING".into()]).unwrap();
        let error = spawn_child_with_environment(&BTreeMap::new(), &missing, &child).unwrap_err();
        assert!(error
            .to_string()
            .contains("secret \"MISSING\" does not exist"));
        assert!(!marker.exists());

        let nul = BTreeMap::from([("TOKEN".into(), VaultValue::Text("bad\0value".into()))]);
        let mapping = parse_environment_mappings(&["TOKEN".into()]).unwrap();
        let error = spawn_child_with_environment(&nul, &mapping, &child).unwrap_err();
        assert!(error.to_string().contains("embedded NUL"));
        assert!(!marker.exists());
    }

    #[test]
    fn child_success_nonzero_and_spawn_failure_are_distinct() {
        let mappings = parse_environment_mappings(&["TOKEN".into()]).unwrap();
        let values = BTreeMap::from([("TOKEN".into(), VaultValue::Text("not printed".into()))]);
        let success = [
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from("exit 0"),
        ];
        let status = spawn_child_with_environment(&values, &mappings, &success)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(RunOutcome::Child(status).exit_code(), 0);

        let failure = [
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from("exit 7"),
        ];
        let status = spawn_child_with_environment(&values, &mappings, &failure)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(RunOutcome::Child(status).exit_code(), 7);

        let signaled = [
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from("kill -TERM $$"),
        ];
        let status = spawn_child_with_environment(&values, &mappings, &signaled)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(RunOutcome::Child(status).exit_code(), 143);

        let nonexistent = [OsString::from("nit-exec-program-that-does-not-exist")];
        let error = spawn_child_with_environment(&values, &mappings, &nonexistent).unwrap_err();
        assert!(error.to_string().contains("cannot spawn child process"));
    }

    #[test]
    fn exec_is_read_only_and_does_not_sign() {
        let values = BTreeMap::from([("TOKEN".into(), VaultValue::Text("not printed".into()))]);
        let (vault, repository, signing_count, _directory) = open_test_vault(values);
        let before = repository.read_vault("exec-test").unwrap().unwrap();
        let mappings = parse_environment_mappings(&["TOKEN".into()]).unwrap();
        let status = vault
            .exec_child(&mappings, &[OsString::from("true")])
            .unwrap();
        assert!(status.success());
        assert_eq!(signing_count.load(Ordering::Relaxed), 0);
        let after = repository.read_vault("exec-test").unwrap().unwrap();
        assert_eq!(after.commit_oid, before.commit_oid);
        assert_eq!(after.log, before.log);
    }

    #[test]
    fn exec_no_output_helper() {
        if env::var_os("NIT_EXEC_TEST_HELPER").is_none() {
            return;
        }
        let secret = "NIT_EXEC_REGRESSION_SECRET_7d4370";
        let values = BTreeMap::from([("TOKEN".into(), VaultValue::Text(secret.into()))]);
        let mappings = parse_environment_mappings(&["TOKEN".into()]).unwrap();
        let status = spawn_child_with_environment(&values, &mappings, &[OsString::from("true")])
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn exec_does_not_print_injected_values() {
        let output = ProcessCommand::new(env::current_exe().unwrap())
            .env("NIT_EXEC_TEST_HELPER", "1")
            .args([
                "--exact",
                "runtime::integration_tests::exec_no_output_helper",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let secret = b"NIT_EXEC_REGRESSION_SECRET_7d4370";
        assert!(!output
            .stdout
            .windows(secret.len())
            .any(|part| part == secret));
        assert!(!output
            .stderr
            .windows(secret.len())
            .any(|part| part == secret));
    }

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
        let device = backend.device();
        let mut identity = backend.open();
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
            previous_epoch_heads: Vec::new(),
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
            .write_local_checkpoint("test", &state.trusted_event_hashes)
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

        let error = vault
            .append_put("TOKEN".into(), VaultValue::Text("secret".into()))
            .unwrap_err();
        assert!(error.to_string().contains("recovery is not configured"));
        vault
            .repository
            .write_unrecoverable_ack("test", &vault.state.vault_id)
            .unwrap();
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
        assert!(stored.log.events[1..]
            .iter()
            .all(|event| matches!(event.payload, EventPayload::Mutation { .. })));
        assert!(!stored
            .log
            .encode()
            .unwrap()
            .windows("TOKEN".len())
            .any(|window| window == b"TOKEN"));
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
    fn physically_present_identity_is_proved_and_added_in_one_event() {
        let directory = TempDir::new().unwrap();
        ProcessCommand::new("git")
            .args(["init", "--quiet"])
            .arg(directory.path())
            .status()
            .unwrap();
        let repository = GitRepository::discover(directory.path()).unwrap();
        let alice_backend = TestIdentityBackend::from_seed(31, "alice");
        let alice_device = alice_backend.device();
        let mut alice = alice_backend.open();
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
            previous_epoch_heads: Vec::new(),
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
            .write_local_checkpoint("onboard", &state.trusted_event_hashes)
            .unwrap();
        let mut vault = OpenVault {
            repository,
            vault_name: "onboard".into(),
            commit_oid,
            log,
            state,
            values: BTreeMap::new(),
            epoch_key,
            identity: alice,
        };

        let bob_backend = TestIdentityBackend::from_seed(32, "bob");
        let bob_device = bob_backend.device();
        let mut bob = FailCheckpointOnce {
            inner: bob_backend.open(),
            fail: true,
        };
        let error = vault
            .add_member(
                member_identity(&bob_device, "Bob".into()),
                Role::Owner,
                &mut bob,
            )
            .unwrap_err();

        assert!(error.to_string().contains("checkpointing is incomplete"));
        assert_eq!(vault.state.membership_epoch, 2);
        assert_eq!(vault.log.events.len(), 2);
        assert_eq!(
            vault
                .state
                .member_for_public_keys(
                    &bob_device.signing_public_key,
                    &bob_device.encryption_public_key,
                )
                .map(|member| member.role),
            Some(Role::Owner)
        );

        advance_identity_checkpoint(&mut bob, &vault.state, "onboard").unwrap();
        assert_eq!(
            bob.read_trust_record("onboard")
                .unwrap()
                .unwrap()
                .membership_epoch,
            2
        );

        let bob_member = member_identity(&bob_device, "Bob".into());
        vault
            .finish_identity_rotation(alice_device.signing_public_key, &bob_member, &mut bob)
            .unwrap();
        assert_eq!(vault.state.membership_epoch, 3);
        assert!(vault
            .state
            .member_for_signing_key(&alice_device.signing_public_key)
            .is_none());
        assert_eq!(
            vault
                .state
                .member_for_signing_key(&bob_device.signing_public_key)
                .map(|member| member.role),
            Some(Role::Owner)
        );
        assert!(vault
            .state
            .unlock_values(&vault.epoch_key)
            .unwrap()
            .is_empty());
    }
}
