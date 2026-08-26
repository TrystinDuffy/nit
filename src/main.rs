mod app;
mod backends;
mod crypto;
mod identity;
mod keys;

use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use app::{App, Effect, Mode, RequestView, RequesterApp, RequesterEffect};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crypto::{Container, Vault};
use identity::{AuthorizedRecipient, DiscoveredIdentity, IdentityBackend};
use keys::InputKey;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(
    name = "nit",
    version,
    about = "A tiny YubiKey-backed encrypted secret vault"
)]
struct Cli {
    /// Encrypted secret vault to open (created if absent)
    file: PathBuf,

    /// Select an identity by backend and locator (for example yubikey:33127878)
    #[arg(long, value_name = "BACKEND:LOCATOR")]
    identity: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List secret names
    List,
    /// Print one secret value
    Get { name: String },
    /// Create or replace a secret
    Set {
        name: String,
        /// Read the value from stdin instead of a secure terminal prompt
        #[arg(long)]
        stdin: bool,
    },
    /// Delete a secret
    Delete { name: String },
    /// Open an invitation slot
    Invite {
        #[arg(long, default_value_t = 30)]
        minutes: u64,
        #[arg(long, default_value_t = 4)]
        words: usize,
    },
    /// List open invitations
    Invitations,
    /// List recipients
    Recipients,
    /// Rename a recipient selected by name or fingerprint
    RenameRecipient { recipient: String, name: String },
    /// Remove a recipient selected by name or fingerprint
    RemoveRecipient { recipient: String },
    /// List pending access requests
    Requests,
    /// Approve a pending request selected by ID prefix
    Approve { request: String },
    /// Reject a pending request selected by ID prefix
    Reject { request: String },
    /// Close an invitation selected by ID prefix
    CloseInvitation { invitation: String },
    /// Request access through an invitation
    RequestAccess {
        /// Invitation ID or unique ID prefix
        invitation: String,
        /// Friendly name for the requesting identity
        #[arg(long)]
        name: String,
        /// Read the invitation phrase from stdin instead of a secure terminal prompt
        #[arg(long)]
        phrase_stdin: bool,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nit: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let automated = cli.command.is_some();
    if cli.file.exists() {
        let container = read_container(&cli.file)?;
        open_existing(container, &cli.file, cli.command, cli.identity, automated)
    } else {
        create_and_open(&cli.file, cli.command, cli.identity, automated)
    }
}

#[derive(Clone, Debug)]
struct IdentityChoice {
    identity: DiscoveredIdentity,
    route_index: Option<usize>,
    vault_access: Option<String>,
}

fn identity_backends() -> Vec<Box<dyn IdentityBackend>> {
    vec![Box::new(backends::yubikey::YubiKeyBackend)]
}

fn identity_backend(id: &str) -> Result<Box<dyn IdentityBackend>> {
    identity_backends()
        .into_iter()
        .find(|backend| backend.id() == id)
        .with_context(|| format!("identity backend {id:?} is not available"))
}

fn discover_identities() -> Result<Vec<DiscoveredIdentity>> {
    let mut identities = Vec::new();
    for backend in identity_backends() {
        identities.extend(backend.discover()?);
    }
    identities.sort_by_key(DiscoveredIdentity::selector);
    Ok(identities)
}

fn open_existing(
    container: Container,
    path: &Path,
    command: Option<Command>,
    requested_identity: Option<String>,
    automated: bool,
) -> Result<()> {
    let identities = discover_identities()?;
    if let Some(selector) = requested_identity {
        let identity = find_identity(&identities, &selector)?.clone();
        if let Some(route_index) = authorized_route(&identity, &container.routes) {
            return unlock(container, path, command, identity, route_index);
        }
        return run_requester(container, path, command, Some(selector), automated);
    }

    let usable = identity_choices_for_vault(&identities, &container.routes);
    if usable.is_empty() {
        return run_requester(container, path, command, None, automated);
    }

    let choice = choose_identity(usable, automated, "Select an identity for this vault")?;
    if let Some(route_index) = choice.route_index {
        unlock(container, path, command, choice.identity, route_index)
    } else {
        run_requester(
            container,
            path,
            command,
            Some(choice.identity.selector()),
            automated,
        )
    }
}

fn unlock(
    container: Container,
    path: &Path,
    command: Option<Command>,
    discovered: DiscoveredIdentity,
    route_index: usize,
) -> Result<()> {
    let recipient = container
        .routes
        .get(route_index)
        .context("invalid recipient route")?;
    let backend = identity_backend(&discovered.backend)?;
    eprintln!(
        "Unlocking {} with {} (recipient #{})…",
        path.display(),
        discovered.display_name,
        route_index + 1
    );
    let identity = backend.unlock(&discovered, recipient, route_index)?;
    let (vault, container) = container.open(identity.as_ref())?;
    run_authorized(vault, container, path, command)
}

fn identity_choices_for_vault(
    identities: &[DiscoveredIdentity],
    routes: &[AuthorizedRecipient],
) -> Vec<IdentityChoice> {
    identities
        .iter()
        .filter(|identity| identity.state.is_provisionable())
        .map(|identity| {
            let route_index = authorized_route(identity, routes);
            let vault_access = Some(match route_index {
                Some(index) => format!("authorized recipient #{}", index + 1),
                None => "not authorized".into(),
            });
            IdentityChoice {
                identity: identity.clone(),
                route_index,
                vault_access,
            }
        })
        .collect()
}

fn authorized_route(
    identity: &DiscoveredIdentity,
    routes: &[AuthorizedRecipient],
) -> Option<usize> {
    let backend = identity_backend(&identity.backend).ok()?;
    routes
        .iter()
        .position(|recipient| backend.matches(identity, recipient))
}

fn find_identity<'a>(
    identities: &'a [DiscoveredIdentity],
    selector: &str,
) -> Result<&'a DiscoveredIdentity> {
    let matches = identities
        .iter()
        .filter(|identity| {
            identity.selector().eq_ignore_ascii_case(selector)
                || identity.locator.eq_ignore_ascii_case(selector)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [identity] => Ok(*identity),
        [] if identities.is_empty() => bail!("no identities were discovered"),
        [] => bail!(
            "identity {selector:?} was not found; discovered identities are {}",
            identities
                .iter()
                .map(DiscoveredIdentity::selector)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => bail!("identity selector {selector:?} is ambiguous; include the backend prefix"),
    }
}

fn choose_provisionable_identity(
    requested_identity: Option<String>,
    automated: bool,
    purpose: &str,
) -> Result<DiscoveredIdentity> {
    let identities = discover_identities()?;
    if let Some(selector) = requested_identity {
        let identity = find_identity(&identities, &selector)?;
        ensure!(
            identity.state.is_provisionable(),
            "{} cannot be provisioned: {}",
            identity.display_name,
            identity.state.description()
        );
        return Ok(identity.clone());
    }
    let choices = identities
        .iter()
        .filter(|identity| identity.state.is_provisionable())
        .map(|identity| IdentityChoice {
            identity: identity.clone(),
            route_index: None,
            vault_access: None,
        })
        .collect::<Vec<_>>();
    if choices.is_empty() && !identities.is_empty() {
        bail!(
            "no discovered identity can be provisioned: {}",
            identities
                .iter()
                .map(|identity| format!(
                    "{} ({})",
                    identity.selector(),
                    identity.state.description()
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    choose_identity(choices, automated, purpose).map(|choice| choice.identity)
}

fn choose_identity(
    choices: Vec<IdentityChoice>,
    automated: bool,
    purpose: &str,
) -> Result<IdentityChoice> {
    match choices.len() {
        0 => bail!("no usable identities were discovered"),
        1 => Ok(choices.into_iter().next().expect("length checked")),
        _ if automated => bail!(
            "multiple usable identities were discovered ({}); select one with --identity <backend:locator>",
            choices
                .iter()
                .map(|choice| choice.identity.selector())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => {
            require_terminal()?;
            choose_identity_tui(choices, purpose)
        }
    }
}

fn read_container(path: &Path) -> Result<Container> {
    let metadata =
        fs::metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    if metadata.len() > crypto::MAX_FILE_SIZE {
        bail!("{} is larger than the 64 MiB vault limit", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Container::decode(&bytes).with_context(|| format!("cannot decode {}", path.display()))
}

fn create_and_open(
    path: &Path,
    command: Option<Command>,
    requested_identity: Option<String>,
    automated: bool,
) -> Result<()> {
    ensure_parent_exists(path)?;
    let identity = choose_provisionable_identity(
        requested_identity,
        automated,
        "Select an identity for the new vault",
    )?;
    eprintln!(
        "Creating {} with {}…",
        path.display(),
        identity.display_name
    );
    let backend = identity_backend(&identity.backend)?;
    let recipient = backend.provision(&identity, format!("Primary — {}", identity.display_name))?;
    let vault = Vault::new(recipient.clone());
    let container = Container::new(&vault)?;
    save_container(path, &container)?;
    eprintln!("Created vault for {}.", recipient.name);
    run_authorized(vault, container, path, command)
}

fn run_authorized(
    mut vault: Vault,
    mut container: Container,
    path: &Path,
    command: Option<Command>,
) -> Result<()> {
    let expired = vault.prune_expired_invitations(crypto::now_unix());
    if !expired.is_empty() {
        let removed_requests = expired
            .iter()
            .map(|id| container.remove_requests_for_invitation(id))
            .sum::<usize>();
        reseal_and_save(path, &mut container, &vault)?;
        eprintln!(
            "Closed {} expired invitation(s) and removed {} associated request(s).",
            expired.len(),
            removed_requests
        );
    }
    if let Some(command) = command {
        return run_authorized_command(&mut vault, &mut container, path, command);
    }
    let claims = container.decrypt_requests(&vault);
    let requests = container
        .requests
        .iter()
        .cloned()
        .zip(claims)
        .map(|(request, claim)| match claim {
            Ok(claim) => RequestView {
                id: request.id,
                invitation_id: request.invitation_id,
                claim: Some(claim),
                error: None,
            },
            Err(error) => RequestView {
                id: request.id,
                invitation_id: request.invitation_id,
                claim: None,
                error: Some(format!("{error:#}")),
            },
        })
        .collect();
    let mut app = App::new(vault, requests);
    let mut outputs = Vec::new();
    let mut invitation_outputs: Vec<Zeroizing<String>> = Vec::new();

    require_terminal()?;
    run_authorized_tui(
        &mut app,
        path,
        &mut container,
        &mut outputs,
        &mut invitation_outputs,
    )?;

    for phrase in invitation_outputs {
        eprintln!("Invitation phrase: {}", phrase.as_str());
    }
    for mut value in outputs {
        println!("{value}");
        value.zeroize();
    }
    Ok(())
}

fn run_authorized_command(
    vault: &mut Vault,
    container: &mut Container,
    path: &Path,
    command: Command,
) -> Result<()> {
    match command {
        Command::List => {
            for name in vault.names() {
                println!("{name}");
            }
        }
        Command::Get { name } => {
            let mut value = vault
                .get(&name)
                .with_context(|| format!("secret {name:?} does not exist"))?
                .to_owned();
            println!("{value}");
            value.zeroize();
        }
        Command::Set { name, stdin } => {
            let mut value = if stdin {
                read_stdin_value("secret value")?
            } else {
                Zeroizing::new(
                    rpassword::prompt_password("Secret value: ")
                        .context("failed to read secret value")?,
                )
            };
            let value = std::mem::take(&mut *value);
            if let Some(mut replaced) = vault.insert(name, value) {
                replaced.zeroize();
            }
            reseal_and_save(path, container, vault)?;
        }
        Command::Delete { name } => {
            let mut removed = vault
                .remove(&name)
                .with_context(|| format!("secret {name:?} does not exist"))?;
            removed.zeroize();
            reseal_and_save(path, container, vault)?;
        }
        Command::Invite { minutes, words } => {
            let (invitation, mut phrase) =
                vault.create_invitation(&container.vault_id, minutes, words)?;
            reseal_and_save(path, container, vault)?;
            println!("{} {}", invitation.short_id(), phrase);
            phrase.zeroize();
        }
        Command::Invitations => print_invitations(&container.invitations),
        Command::Recipients => {
            for recipient in vault.recipients() {
                println!(
                    "{}  {}  {}:{}",
                    recipient.fingerprint(),
                    recipient.name,
                    recipient.backend,
                    recipient.locator
                );
            }
        }
        Command::RenameRecipient { recipient, name } => {
            let index = select_recipient_index(vault.recipients(), &recipient)?;
            vault.rename_recipient(index, name)?;
            reseal_and_save(path, container, vault)?;
        }
        Command::RemoveRecipient { recipient } => {
            let index = select_recipient_index(vault.recipients(), &recipient)?;
            let age_recipient = vault.recipients()[index].age_recipient.clone();
            let removed = vault.remove_recipient(&age_recipient)?;
            let closed = vault.rotate_inbox_and_clear_invitations();
            let requests = container.clear_requests();
            reseal_and_save(path, container, vault)?;
            eprintln!(
                "Removed {} [{}]; rotated inbox; closed {} invitation(s) and removed {} request(s).",
                removed.name,
                removed.fingerprint(),
                closed.len(),
                requests
            );
        }
        Command::Requests => {
            for (request, claim) in container
                .requests
                .iter()
                .zip(container.decrypt_requests(vault))
            {
                match claim {
                    Ok(claim) => println!(
                        "{}  {}  [{}]  invitation {}",
                        hex::encode_upper(request.id),
                        claim.recipient.name,
                        claim.recipient.fingerprint(),
                        hex::encode_upper(claim.invitation_id)
                    ),
                    Err(error) => {
                        println!("{}  unreadable: {error:#}", hex::encode_upper(request.id))
                    }
                }
            }
        }
        Command::Approve { request } => {
            let request_id = select_request_id(&container.requests, &request)?;
            let claim = container
                .requests
                .iter()
                .zip(container.decrypt_requests(vault))
                .find(|(pending, _)| pending.id == request_id)
                .and_then(|(_, claim)| claim.ok())
                .context("selected request is unreadable")?;
            let result = vault.approve_request(&container.vault_id, &claim);
            if result.is_ok() {
                container.remove_requests_for_invitation(&claim.invitation_id);
            }
            reseal_and_save(path, container, vault)?;
            result?;
            eprintln!(
                "Approved {} [{}].",
                claim.recipient.name,
                claim.recipient.fingerprint()
            );
        }
        Command::Reject { request } => {
            let request_id = select_request_id(&container.requests, &request)?;
            container.remove_request(&request_id);
            save_container(path, container)?;
        }
        Command::CloseInvitation { invitation } => {
            let invitation = select_invitation(&container.invitations, &invitation)?.clone();
            vault.close_invitation(&invitation.id);
            container.remove_requests_for_invitation(&invitation.id);
            reseal_and_save(path, container, vault)?;
        }
        Command::RequestAccess { .. } => {
            bail!("the selected YubiKey already has access to this vault")
        }
    }
    Ok(())
}

fn print_invitations(invitations: &[crypto::PublicInvitation]) {
    for invitation in invitations {
        println!(
            "{}  expires {}",
            hex::encode_upper(invitation.id),
            invitation.expires_at
        );
    }
}

fn select_invitation<'a>(
    invitations: &'a [crypto::PublicInvitation],
    selector: &str,
) -> Result<&'a crypto::PublicInvitation> {
    select_unique(
        invitations,
        selector,
        |invitation| hex::encode_upper(invitation.id),
        "invitation",
    )
}

fn select_request_id(requests: &[crypto::PendingRequest], selector: &str) -> Result<[u8; 16]> {
    Ok(select_unique(
        requests,
        selector,
        |request| hex::encode_upper(request.id),
        "request",
    )?
    .id)
}

fn select_recipient_index(recipients: &[AuthorizedRecipient], selector: &str) -> Result<usize> {
    let normalized = selector.to_ascii_uppercase();
    let matches = recipients
        .iter()
        .enumerate()
        .filter(|(_, recipient)| {
            recipient.name.eq_ignore_ascii_case(selector)
                || recipient.fingerprint().starts_with(&normalized)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => bail!("no recipient matches {selector:?}"),
        _ => bail!("recipient selector {selector:?} is ambiguous"),
    }
}

fn select_unique<'a, T>(
    values: &'a [T],
    selector: &str,
    identifier: impl Fn(&T) -> String,
    what: &str,
) -> Result<&'a T> {
    ensure!(!selector.is_empty(), "{what} selector cannot be empty");
    let normalized = selector.to_ascii_uppercase();
    let matches = values
        .iter()
        .filter(|value| identifier(value).starts_with(&normalized))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [value] => Ok(*value),
        [] => bail!("no {what} matches {selector:?}"),
        _ => bail!("{what} selector {selector:?} is ambiguous"),
    }
}

fn read_stdin_value(what: &str) -> Result<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut value)
        .with_context(|| format!("failed to read {what} from stdin"))?;
    Ok(value)
}

fn handle_authorized_input(
    app: &mut App,
    input: InputKey,
    path: &Path,
    container: &mut Container,
    outputs: &mut Vec<String>,
    invitation_outputs: &mut Vec<Zeroizing<String>>,
) -> Result<bool> {
    match app.input(input) {
        Effect::None => Ok(false),
        Effect::Changed => {
            reseal_and_save(path, container, app.vault())?;
            Ok(false)
        }
        Effect::Output(value) => {
            outputs.push(value);
            Ok(false)
        }
        Effect::CreateInvitation { minutes, words } => {
            let (invitation, phrase) =
                app.vault_mut()
                    .create_invitation(&container.vault_id, minutes, words)?;
            reseal_and_save(path, container, app.vault())?;
            invitation_outputs.push(Zeroizing::new(phrase.clone()));
            app.invitation_created(&invitation, phrase);
            Ok(false)
        }
        Effect::ApproveRequest(id) => {
            let Some(claim) = app.request_claim(&id) else {
                app.set_status("The selected request is unreadable");
                return Ok(false);
            };
            let result = app.vault_mut().approve_request(&container.vault_id, &claim);
            if result.is_ok() {
                container.remove_requests_for_invitation(&claim.invitation_id);
                app.remove_requests_for_invitation(&claim.invitation_id);
            }
            // An invalid phrase consumes an attempt, so authenticated state is saved on
            // both success and failure.
            reseal_and_save(path, container, app.vault())?;
            match result {
                Ok(()) => app.set_status(format!(
                    "Approved {} [{}]; encrypted file saved",
                    claim.recipient.name,
                    claim.recipient.fingerprint()
                )),
                Err(error) => app.set_status(format!("Request not approved: {error:#}")),
            }
            Ok(false)
        }
        Effect::RejectRequest(id) => {
            container.remove_request(&id);
            app.remove_request(&id);
            save_container(path, container)?;
            app.set_status("Request rejected and removed; encrypted file saved");
            Ok(false)
        }
        Effect::CloseInvitation(id) => {
            if app.vault_mut().close_invitation(&id) {
                let removed = container.remove_requests_for_invitation(&id);
                app.remove_requests_for_invitation(&id);
                reseal_and_save(path, container, app.vault())?;
                app.set_status(format!(
                    "Invitation closed; removed {removed} associated request(s); encrypted file saved"
                ));
            } else {
                app.set_status("Invitation was already closed");
            }
            Ok(false)
        }
        Effect::RemoveRecipient(age_recipient) => {
            match app.vault_mut().remove_recipient(&age_recipient) {
                Ok(recipient) => {
                    let closed_invitations = app.vault_mut().rotate_inbox_and_clear_invitations();
                    let removed_requests = container.clear_requests();
                    app.clear_requests();
                    reseal_and_save(path, container, app.vault())?;
                    app.set_status(format!(
                        "Removed {} [{}]; rotated request inbox; closed {} invitation(s) and removed {} request(s)",
                        recipient.name,
                        recipient.fingerprint(),
                        closed_invitations.len(),
                        removed_requests
                    ));
                }
                Err(error) => app.set_status(format!("Recipient not removed: {error:#}")),
            }
            Ok(false)
        }
        Effect::Quit => Ok(true),
    }
}

fn run_requester(
    mut container: Container,
    path: &Path,
    command: Option<Command>,
    requested_identity: Option<String>,
    automated: bool,
) -> Result<()> {
    let open_invitations = container
        .invitations
        .iter()
        .filter(|invitation| !invitation.is_expired())
        .cloned()
        .collect::<Vec<_>>();
    if open_invitations.is_empty() {
        bail!(
            "no discovered identity is authorized for this vault and there are no unexpired invitations"
        );
    }
    if let Some(command) = command {
        let (invitation, name, phrase_stdin) = match command {
            Command::Invitations => {
                print_invitations(&open_invitations);
                return Ok(());
            }
            Command::RequestAccess {
                invitation,
                name,
                phrase_stdin,
            } => (invitation, name, phrase_stdin),
            _ => bail!(
                "the selected identity is not authorized; use request-access or select an authorized identity"
            ),
        };
        let invitation = select_invitation(&open_invitations, &invitation)?.clone();
        let mut phrase = if phrase_stdin {
            read_stdin_value("invitation phrase")?
        } else {
            Zeroizing::new(
                rpassword::prompt_password("Invitation phrase: ")
                    .context("failed to read invitation phrase")?,
            )
        };
        submit_request(
            &mut container,
            path,
            &invitation,
            &phrase,
            name,
            requested_identity,
            automated,
        )?;
        phrase.zeroize();
        eprintln!(
            "Access request added to {}; commit and push the file.",
            path.display()
        );
        return Ok(());
    }

    let mut app = RequesterApp::new(open_invitations);
    require_terminal()?;
    run_requester_tui(
        &mut app,
        &mut container,
        path,
        requested_identity,
        automated,
    )
}

fn submit_request(
    container: &mut Container,
    path: &Path,
    invitation: &crypto::PublicInvitation,
    phrase: &str,
    name: String,
    requested_identity: Option<String>,
    automated: bool,
) -> Result<()> {
    crypto::validate_invitation_phrase(phrase)?;
    container.verify_invitation(invitation, phrase)?;
    let identity = choose_provisionable_identity(
        requested_identity,
        automated,
        "Select an identity for the access request",
    )?;
    eprintln!(
        "Preparing {} as the recipient for the access request…",
        identity.display_name
    );
    let backend = identity_backend(&identity.backend)?;
    let recipient = backend.provision(&identity, name)?;
    container.create_request(invitation, phrase, recipient)?;
    save_container(path, container)
}

fn reseal_and_save(path: &Path, container: &mut Container, vault: &Vault) -> Result<()> {
    container.reseal(vault)?;
    save_container(path, container)
}

fn save_container(path: &Path, container: &Container) -> Result<()> {
    let encoded = container.encode()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create temporary file in {}", parent.display()))?;
    temp.write_all(&encoded)
        .context("cannot write encrypted vault")?;
    temp.as_file()
        .sync_all()
        .context("cannot sync encrypted vault")?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot atomically replace {}", path.display()))?;
    Ok(())
}

fn ensure_parent_exists(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.exists() {
            bail!("parent directory {} does not exist", parent.display());
        }
    }
    Ok(())
}

fn require_terminal() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("interactive mode needs a terminal; use an explicit subcommand for automation");
    }
    Ok(())
}

fn event_to_input() -> Result<Option<InputKey>> {
    if !event::poll(Duration::from_millis(250))? {
        return Ok(None);
    }
    let Event::Key(key) = event::read()? else {
        return Ok(None);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(None);
    }
    Ok(match key.code {
        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
            Some(InputKey::Esc)
        }
        KeyCode::Char(character) => Some(InputKey::Char(character)),
        KeyCode::Enter => Some(InputKey::Enter),
        KeyCode::Esc => Some(InputKey::Esc),
        KeyCode::Up => Some(InputKey::Up),
        KeyCode::Down => Some(InputKey::Down),
        KeyCode::Backspace => Some(InputKey::Backspace),
        KeyCode::Tab => Some(InputKey::Tab),
        _ => None,
    })
}

fn choose_identity_tui(choices: Vec<IdentityChoice>, purpose: &str) -> Result<IdentityChoice> {
    let mut selected = 0usize;
    let selected = with_terminal(|terminal| loop {
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(4), Constraint::Length(3)])
                .split(frame.area());
            let items = choices
                .iter()
                .map(|choice| {
                    let vault_access = choice
                        .vault_access
                        .as_deref()
                        .map(|status| format!(" — {status}"))
                        .unwrap_or_default();
                    ListItem::new(format!(
                        "  {}  {}{}",
                        choice.identity.display_name, choice.identity.detail, vault_access
                    ))
                })
                .collect::<Vec<_>>();
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(purpose))
                .highlight_symbol("› ")
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                );
            let mut state = ListState::default();
            state.select(Some(selected));
            frame.render_stateful_widget(list, areas[0], &mut state);
            frame.render_widget(
                Paragraph::new(" <j>/<k> or <↑>/<↓> select   <Enter> confirms   <Esc> cancels")
                    .block(Block::default().borders(Borders::ALL).title(" Keys ")),
                areas[1],
            );
        })?;
        let Some(input) = event_to_input()? else {
            continue;
        };
        match input {
            InputKey::Down | InputKey::Char('j') => {
                selected = (selected + 1).min(choices.len() - 1);
            }
            InputKey::Up | InputKey::Char('k') => {
                selected = selected.saturating_sub(1);
            }
            InputKey::Enter => break Ok(selected),
            InputKey::Esc | InputKey::Char('q') => bail!("identity selection cancelled"),
            _ => {}
        }
    })?;
    Ok(choices[selected].clone())
}

fn run_authorized_tui(
    app: &mut App,
    path: &Path,
    container: &mut Container,
    outputs: &mut Vec<String>,
    invitation_outputs: &mut Vec<Zeroizing<String>>,
) -> Result<()> {
    with_terminal(|terminal| {
        loop {
            terminal.draw(|frame| app::draw(frame, app, path))?;
            let Some(input) = event_to_input()? else {
                continue;
            };
            if handle_authorized_input(app, input, path, container, outputs, invitation_outputs)? {
                break;
            }
        }
        Ok(())
    })?;
    if !matches!(app.mode(), Mode::List) {
        app.cancel();
    }
    Ok(())
}

fn run_requester_tui(
    app: &mut RequesterApp,
    container: &mut Container,
    path: &Path,
    requested_identity: Option<String>,
    automated: bool,
) -> Result<()> {
    let result = with_terminal(|terminal| loop {
        terminal.draw(|frame| app::draw_requester(frame, app, path))?;
        let Some(input) = event_to_input()? else {
            continue;
        };
        match app.input(input) {
            RequesterEffect::None => {}
            RequesterEffect::Quit => break Ok(None),
            RequesterEffect::Submit {
                invitation,
                phrase,
                name,
            } => break Ok(Some((invitation, phrase, name))),
        }
    })?;
    if let Some((invitation, mut phrase, name)) = result {
        submit_request(
            container,
            path,
            &invitation,
            &phrase,
            name,
            requested_identity,
            automated,
        )?;
        phrase.zeroize();
        eprintln!(
            "Access request added to {}; commit and push the file.",
            path.display()
        );
    }
    Ok(())
}

fn with_terminal<T>(
    operation: impl FnOnce(&mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<T>,
) -> Result<T> {
    enable_raw_mode().context("cannot enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("cannot enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("cannot initialize terminal")?;
    let result = operation(&mut terminal);
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_route_matches_backend_locator_and_recipient() {
        let identity = DiscoveredIdentity {
            backend: "yubikey".into(),
            locator: "123".into(),
            display_name: "YubiKey 123".into(),
            detail: "ready".into(),
            state: identity::IdentityState::Ready {
                age_recipient: "age1test".into(),
            },
        };
        let routes = vec![AuthorizedRecipient {
            name: "Alice".into(),
            backend: "yubikey".into(),
            locator: "123".into(),
            age_recipient: "age1test".into(),
        }];
        assert_eq!(authorized_route(&identity, &routes), Some(0));

        let mut wrong_identity = identity.clone();
        wrong_identity.locator = "456".into();
        assert_eq!(authorized_route(&wrong_identity, &routes), None);

        let choices = identity_choices_for_vault(&[identity, wrong_identity], &routes);
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].route_index, Some(0));
        assert_eq!(
            choices[0].vault_access.as_deref(),
            Some("authorized recipient #1")
        );
        assert_eq!(choices[1].route_index, None);
        assert_eq!(choices[1].vault_access.as_deref(), Some("not authorized"));
    }
}
