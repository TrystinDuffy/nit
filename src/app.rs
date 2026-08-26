use std::path::Path;

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{validate_invitation_phrase, Invitation, PublicInvitation, RequestClaim, Vault},
    keys::InputKey,
};

const MAX_NAME_LEN: usize = 1_024;
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;
const MAX_FRIENDLY_NAME: usize = 128;

#[derive(Debug)]
pub enum Effect {
    None,
    Changed,
    Output(String),
    CreateInvitation { minutes: u64, words: usize },
    ApproveRequest([u8; 16]),
    RejectRequest([u8; 16]),
    CloseInvitation([u8; 16]),
    RemoveRecipient(String),
    Quit,
}

#[derive(Debug)]
pub enum Mode {
    List,
    Name {
        buffer: String,
    },
    Value {
        name: String,
        buffer: String,
        editing: bool,
    },
    ConfirmDelete {
        name: String,
    },
    Access,
    InviteDuration {
        buffer: String,
    },
    InviteWords {
        minutes: u64,
        buffer: String,
    },
    RecipientName {
        index: usize,
        buffer: String,
    },
    ConfirmApprove {
        request_id: [u8; 16],
    },
    ConfirmReject {
        request_id: [u8; 16],
    },
    ConfirmClose {
        invitation_id: [u8; 16],
    },
    ConfirmRemoveRecipient {
        age_recipient: String,
    },
}

#[derive(Clone, Debug)]
pub struct RequestView {
    pub id: [u8; 16],
    pub invitation_id: [u8; 16],
    pub claim: Option<RequestClaim>,
    pub error: Option<String>,
}

#[derive(Clone, Copy)]
enum AccessTarget {
    Recipient(usize),
    Invitation([u8; 16]),
    Request([u8; 16]),
}

pub struct App {
    vault: Vault,
    selected: usize,
    revealed: Option<String>,
    mode: Mode,
    status: String,
    access_selected: usize,
    requests: Vec<RequestView>,
    invitation_phrase: Option<Zeroizing<String>>,
}

impl App {
    pub fn new(vault: Vault, requests: Vec<RequestView>) -> Self {
        let pending = requests.len();
        Self {
            vault,
            selected: 0,
            revealed: None,
            mode: Mode::List,
            status: if pending == 0 {
                "Ready".into()
            } else {
                format!("{pending} access request(s) pending")
            },
            access_selected: 0,
            requests,
            invitation_phrase: None,
        }
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    pub fn request_claim(&self, id: &[u8; 16]) -> Option<RequestClaim> {
        self.requests
            .iter()
            .find(|request| &request.id == id)
            .and_then(|request| request.claim.clone())
    }

    pub fn remove_request(&mut self, id: &[u8; 16]) {
        self.requests.retain(|request| &request.id != id);
        self.clamp_access_selection();
    }

    pub fn remove_requests_for_invitation(&mut self, invitation_id: &[u8; 16]) {
        self.requests
            .retain(|request| &request.invitation_id != invitation_id);
        self.clamp_access_selection();
    }

    pub fn clear_requests(&mut self) {
        self.requests.clear();
        self.clamp_access_selection();
    }

    pub fn invitation_created(&mut self, invitation: &PublicInvitation, phrase: String) {
        self.invitation_phrase = Some(Zeroizing::new(phrase));
        self.mode = Mode::Access;
        self.status = format!(
            "Invitation {} is open; share the phrase verbally",
            invitation.short_id()
        );
        self.access_selected = self
            .access_targets()
            .iter()
            .position(
                |target| matches!(target, AccessTarget::Invitation(id) if id == &invitation.id),
            )
            .unwrap_or(0);
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    pub fn cancel(&mut self) {
        let old = std::mem::replace(&mut self.mode, Mode::List);
        zeroize_mode(old);
        self.clear_invitation_phrase();
        self.status = "Cancelled".into();
    }

    pub fn input(&mut self, key: InputKey) -> Effect {
        match &mut self.mode {
            Mode::List => self.input_list(key),
            Mode::Name { buffer } => match key {
                InputKey::Esc => {
                    self.cancel();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let name = buffer.trim().to_owned();
                    if name.is_empty() {
                        self.status = "Name cannot be empty".into();
                    } else if self.vault.contains(&name) {
                        self.status = format!("{name} already exists");
                    } else {
                        buffer.zeroize();
                        self.mode = Mode::Value {
                            name,
                            buffer: String::new(),
                            editing: false,
                        };
                        self.status = "Type the secret value; <Enter> saves, <Esc> cancels".into();
                    }
                    Effect::None
                }
                InputKey::Char(character) => {
                    if buffer.len() + character.len_utf8() <= MAX_NAME_LEN {
                        buffer.push(character);
                    } else {
                        self.status = "Name is too long".into();
                    }
                    Effect::None
                }
                InputKey::Tab => {
                    if buffer.len() < MAX_NAME_LEN {
                        buffer.push('\t');
                    }
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::Value {
                name,
                buffer,
                editing,
            } => match key {
                InputKey::Esc => {
                    self.cancel();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let selected_name = name.clone();
                    let value = std::mem::take(buffer);
                    let was_edit = *editing;
                    if let Some(mut replaced) = self.vault.insert(selected_name.clone(), value) {
                        replaced.zeroize();
                    }
                    self.mode = Mode::List;
                    self.select_name(&selected_name);
                    self.revealed = None;
                    self.status = if was_edit {
                        format!("Updated {selected_name}; encrypted file saved")
                    } else {
                        format!("Created {selected_name}; encrypted file saved")
                    };
                    Effect::Changed
                }
                InputKey::Char(character) => {
                    if buffer.len() + character.len_utf8() <= MAX_VALUE_LEN {
                        buffer.push(character);
                    } else {
                        self.status = "Value is too long".into();
                    }
                    Effect::None
                }
                InputKey::Tab => {
                    if buffer.len() < MAX_VALUE_LEN {
                        buffer.push('\t');
                    }
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::ConfirmDelete { name } => match key {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let deleted_name = name.clone();
                    if let Some(mut value) = self.vault.remove(&deleted_name) {
                        value.zeroize();
                    }
                    self.mode = Mode::List;
                    self.revealed = None;
                    self.clamp_selection();
                    self.status = format!("Deleted {deleted_name}; encrypted file saved");
                    Effect::Changed
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    self.cancel();
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::Access => self.input_access(key),
            Mode::InviteDuration { buffer } => match key {
                InputKey::Esc => {
                    buffer.zeroize();
                    self.mode = Mode::Access;
                    self.status = "Invitation cancelled".into();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let minutes = if buffer.is_empty() {
                        30
                    } else {
                        match buffer.parse::<u64>() {
                            Ok(value) if value > 0 && value <= 10_080 => value,
                            _ => {
                                self.status = "Enter 1–10080 minutes".into();
                                return Effect::None;
                            }
                        }
                    };
                    buffer.zeroize();
                    self.mode = Mode::InviteWords {
                        minutes,
                        buffer: String::new(),
                    };
                    self.status = "Words in invitation phrase: 4–6; <Enter> uses 4".into();
                    Effect::None
                }
                InputKey::Char(character) if character.is_ascii_digit() => {
                    if buffer.len() < 5 {
                        buffer.push(character);
                    }
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::InviteWords { minutes, buffer } => match key {
                InputKey::Esc => {
                    buffer.zeroize();
                    self.mode = Mode::Access;
                    self.status = "Invitation cancelled".into();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let words = if buffer.is_empty() {
                        4
                    } else {
                        match buffer.parse::<usize>() {
                            Ok(value @ 4..=6) => value,
                            _ => {
                                self.status = "Enter 4, 5, or 6 words".into();
                                return Effect::None;
                            }
                        }
                    };
                    let duration = *minutes;
                    buffer.zeroize();
                    self.mode = Mode::Access;
                    Effect::CreateInvitation {
                        minutes: duration,
                        words,
                    }
                }
                InputKey::Char(character) if ('4'..='6').contains(&character) => {
                    buffer.clear();
                    buffer.push(character);
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::RecipientName { index, buffer } => match key {
                InputKey::Esc => {
                    buffer.zeroize();
                    self.mode = Mode::Access;
                    self.status = "Rename cancelled".into();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let name = buffer.trim().to_owned();
                    if name.is_empty() {
                        self.status = "Friendly name cannot be empty".into();
                        Effect::None
                    } else {
                        buffer.zeroize();
                        match self.vault.rename_recipient(*index, name) {
                            Ok(()) => {
                                self.mode = Mode::Access;
                                self.status = "Recipient renamed; encrypted file saved".into();
                                Effect::Changed
                            }
                            Err(error) => {
                                self.status = format!("Cannot rename recipient: {error:#}");
                                Effect::None
                            }
                        }
                    }
                }
                InputKey::Char(character) => {
                    if buffer.len() + character.len_utf8() <= MAX_FRIENDLY_NAME {
                        buffer.push(character);
                    }
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::ConfirmApprove { request_id } => match key {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let id = *request_id;
                    self.mode = Mode::Access;
                    Effect::ApproveRequest(id)
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    self.mode = Mode::Access;
                    self.status = "Approval cancelled".into();
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::ConfirmReject { request_id } => match key {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let id = *request_id;
                    self.mode = Mode::Access;
                    Effect::RejectRequest(id)
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    self.mode = Mode::Access;
                    self.status = "Rejection cancelled".into();
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::ConfirmClose { invitation_id } => match key {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let id = *invitation_id;
                    self.mode = Mode::Access;
                    Effect::CloseInvitation(id)
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    self.mode = Mode::Access;
                    self.status = "Close cancelled".into();
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::ConfirmRemoveRecipient { age_recipient } => match key {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let recipient = age_recipient.clone();
                    self.mode = Mode::Access;
                    Effect::RemoveRecipient(recipient)
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    self.mode = Mode::Access;
                    self.status = "Recipient removal cancelled".into();
                    Effect::None
                }
                _ => Effect::None,
            },
        }
    }

    fn input_list(&mut self, key: InputKey) -> Effect {
        match key {
            InputKey::Down | InputKey::Char('j') => {
                let length = self.vault.names().count();
                if length > 0 {
                    self.selected = (self.selected + 1).min(length - 1);
                }
                self.revealed = None;
                Effect::None
            }
            InputKey::Up | InputKey::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                self.revealed = None;
                Effect::None
            }
            InputKey::Char('n') => {
                self.mode = Mode::Name {
                    buffer: String::new(),
                };
                self.status = "Enter a new secret name; <Enter> continues, <Esc> cancels".into();
                Effect::None
            }
            InputKey::Char('e') => {
                if let Some(name) = self.selected_name().map(str::to_owned) {
                    self.mode = Mode::Value {
                        name,
                        buffer: String::new(),
                        editing: true,
                    };
                    self.status =
                        "Enter the replacement value; <Enter> saves, <Esc> cancels".into();
                } else {
                    self.status = "The vault has no secrets to edit".into();
                }
                Effect::None
            }
            InputKey::Char('d') => {
                if let Some(name) = self.selected_name().map(str::to_owned) {
                    self.mode = Mode::ConfirmDelete { name };
                    self.status =
                        "Delete this secret? <y>/<Enter> confirms, <n>/<Esc> cancels".into();
                } else {
                    self.status = "The vault has no secrets to delete".into();
                }
                Effect::None
            }
            InputKey::Char('r') => {
                if let Some(name) = self.selected_name().map(str::to_owned) {
                    self.revealed = if self.revealed.as_deref() == Some(&name) {
                        None
                    } else {
                        Some(name)
                    };
                } else {
                    self.status = "The vault has no secrets to reveal".into();
                }
                Effect::None
            }
            InputKey::Char('y') => {
                if let Some(value) = self
                    .selected_name()
                    .and_then(|name| self.vault.get(name))
                    .map(str::to_owned)
                {
                    self.status = "Selected value queued for stdout after exit".into();
                    Effect::Output(value)
                } else {
                    self.status = "The vault has no secrets to output".into();
                    Effect::None
                }
            }
            InputKey::Char('a') => {
                self.mode = Mode::Access;
                self.clear_invitation_phrase();
                self.status = "Managing recipients, invitations, and requests".into();
                Effect::None
            }
            InputKey::Char('q') | InputKey::Esc => Effect::Quit,
            _ => Effect::None,
        }
    }

    fn input_access(&mut self, key: InputKey) -> Effect {
        match key {
            InputKey::Down | InputKey::Char('j') => {
                let length = self.access_targets().len();
                if length > 0 {
                    self.access_selected = (self.access_selected + 1).min(length - 1);
                }
                self.clear_invitation_phrase();
                Effect::None
            }
            InputKey::Up | InputKey::Char('k') => {
                self.access_selected = self.access_selected.saturating_sub(1);
                self.clear_invitation_phrase();
                Effect::None
            }
            InputKey::Char('n') => {
                self.mode = Mode::InviteDuration {
                    buffer: String::new(),
                };
                self.status = "Invitation duration in minutes; <Enter> uses 30".into();
                Effect::None
            }
            InputKey::Char('e') => match self.selected_access_target() {
                Some(AccessTarget::Recipient(index)) => {
                    self.mode = Mode::RecipientName {
                        index,
                        buffer: String::new(),
                    };
                    self.status = "Enter a new friendly recipient name".into();
                    Effect::None
                }
                _ => {
                    self.status = "Select a recipient to rename".into();
                    Effect::None
                }
            },
            InputKey::Char('d') => match self.selected_access_target() {
                Some(AccessTarget::Recipient(index)) => {
                    if self.vault.recipients().len() <= 1 {
                        self.status = "The final recipient cannot be removed".into();
                    } else {
                        let age_recipient = self.vault.recipients()[index].age_recipient.clone();
                        self.mode = Mode::ConfirmRemoveRecipient { age_recipient };
                        self.status =
                            "Remove this recipient from future vault versions? <y>/<Enter> confirms"
                                .into();
                    }
                    Effect::None
                }
                _ => {
                    self.status = "Select a recipient to remove".into();
                    Effect::None
                }
            },
            InputKey::Char('a') => match self.selected_access_target() {
                Some(AccessTarget::Request(id)) => {
                    if self.request_claim(&id).is_some() {
                        self.mode = Mode::ConfirmApprove { request_id: id };
                        self.status =
                            "Approve this untrusted recipient? <y>/<Enter> confirms".into();
                    } else {
                        self.status = "Unreadable requests cannot be approved; reject them".into();
                    }
                    Effect::None
                }
                _ => {
                    self.status = "Select an access request to approve".into();
                    Effect::None
                }
            },
            InputKey::Char('x') => match self.selected_access_target() {
                Some(AccessTarget::Request(id)) => {
                    self.mode = Mode::ConfirmReject { request_id: id };
                    self.status = "Reject and remove this request? <y>/<Enter> confirms".into();
                    Effect::None
                }
                _ => {
                    self.status = "Select an access request to reject".into();
                    Effect::None
                }
            },
            InputKey::Char('c') => match self.selected_access_target() {
                Some(AccessTarget::Invitation(id)) => {
                    self.mode = Mode::ConfirmClose { invitation_id: id };
                    self.status = "Close this invitation? <y>/<Enter> confirms".into();
                    Effect::None
                }
                _ => {
                    self.status = "Select an invitation to close".into();
                    Effect::None
                }
            },
            InputKey::Esc | InputKey::Char('q') => {
                self.mode = Mode::List;
                self.clear_invitation_phrase();
                self.status = "Ready".into();
                Effect::None
            }
            _ => Effect::None,
        }
    }

    fn selected_name(&self) -> Option<&str> {
        self.vault.names().nth(self.selected)
    }

    fn select_name(&mut self, target: &str) {
        self.selected = self
            .vault
            .names()
            .position(|name| name == target)
            .unwrap_or(0);
    }

    fn clamp_selection(&mut self) {
        self.selected = self
            .selected
            .min(self.vault.names().count().saturating_sub(1));
    }

    fn access_targets(&self) -> Vec<AccessTarget> {
        self.vault
            .recipients()
            .iter()
            .enumerate()
            .map(|(index, _)| AccessTarget::Recipient(index))
            .chain(
                self.vault
                    .invitations()
                    .iter()
                    .map(|invitation| AccessTarget::Invitation(invitation.id)),
            )
            .chain(
                self.requests
                    .iter()
                    .map(|request| AccessTarget::Request(request.id)),
            )
            .collect()
    }

    fn selected_access_target(&self) -> Option<AccessTarget> {
        self.access_targets().get(self.access_selected).copied()
    }

    fn clamp_access_selection(&mut self) {
        self.access_selected = self
            .access_selected
            .min(self.access_targets().len().saturating_sub(1));
    }

    fn clear_invitation_phrase(&mut self) {
        self.invitation_phrase = None;
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let mode = std::mem::replace(&mut self.mode, Mode::List);
        zeroize_mode(mode);
        self.clear_invitation_phrase();
    }
}

fn zeroize_mode(mut mode: Mode) {
    match &mut mode {
        Mode::Name { buffer }
        | Mode::InviteDuration { buffer }
        | Mode::InviteWords { buffer, .. }
        | Mode::RecipientName { buffer, .. } => buffer.zeroize(),
        Mode::Value { name, buffer, .. } => {
            name.zeroize();
            buffer.zeroize();
        }
        Mode::ConfirmDelete { name } => name.zeroize(),
        Mode::List
        | Mode::Access
        | Mode::ConfirmApprove { .. }
        | Mode::ConfirmReject { .. }
        | Mode::ConfirmClose { .. }
        | Mode::ConfirmRemoveRecipient { .. } => {}
    }
}

pub fn draw(frame: &mut Frame, app: &App, path: &Path) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(area);

    if matches!(
        app.mode,
        Mode::Access
            | Mode::InviteDuration { .. }
            | Mode::InviteWords { .. }
            | Mode::RecipientName { .. }
            | Mode::ConfirmApprove { .. }
            | Mode::ConfirmReject { .. }
            | Mode::ConfirmClose { .. }
            | Mode::ConfirmRemoveRecipient { .. }
    ) {
        draw_access(frame, app, path, &chunks);
    } else {
        draw_secrets(frame, app, path, &chunks);
    }
}

fn draw_secrets(frame: &mut Frame, app: &App, path: &Path, chunks: &[ratatui::layout::Rect]) {
    let title = format!(" {} ", path.display());
    let items: Vec<ListItem> = app
        .vault
        .names()
        .map(|name| ListItem::new(format!("  {name}")))
        .collect();
    let list = if items.is_empty() {
        List::new(vec![ListItem::new(
            "  (empty — press <n> to create a secret)",
        )])
    } else {
        List::new(items)
    }
    .block(Block::default().borders(Borders::ALL).title(title))
    .highlight_symbol("› ")
    .highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ListState::default();
    if app.vault.names().next().is_some() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let detail = match &app.mode {
        Mode::List => {
            if let Some(name) = app.selected_name() {
                if app.revealed.as_deref() == Some(name) {
                    app.vault.get(name).unwrap_or_default().to_owned()
                } else {
                    "••••••••  (press <r> to reveal)".into()
                }
            } else {
                "No secret selected".into()
            }
        }
        Mode::Name { buffer } => format!("Name: {buffer}_"),
        Mode::Value {
            name,
            buffer,
            editing,
        } => format!(
            "{} {name}: {}_",
            if *editing { "Replace" } else { "Value for" },
            "•".repeat(buffer.chars().count().min(64))
        ),
        Mode::ConfirmDelete { name } => format!("Permanently delete {name} from this vault?"),
        _ => String::new(),
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Secret "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    draw_footer(frame, app, chunks[2], chunks[3]);
}

fn draw_access(frame: &mut Frame, app: &App, path: &Path, chunks: &[ratatui::layout::Rect]) {
    let mut items = Vec::new();
    for recipient in app.vault.recipients() {
        items.push(ListItem::new(format!(
            "  Recipient  {}  [{}]",
            recipient.name,
            recipient.fingerprint()
        )));
    }
    for invitation in app.vault.invitations() {
        items.push(ListItem::new(format!(
            "  Invitation {}  {} attempt(s)  expires {}",
            hex::encode_upper(&invitation.id[..4]),
            invitation.attempts_remaining,
            invitation.expires_at
        )));
    }
    for request in &app.requests {
        let label = request
            .claim
            .as_ref()
            .map(|claim| {
                format!(
                    "Request    {}  {}  [{}]",
                    hex::encode_upper(&request.id[..4]),
                    claim.recipient.name,
                    claim.recipient.fingerprint()
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "Request    {}  unreadable",
                    hex::encode_upper(&request.id[..4])
                )
            });
        items.push(ListItem::new(format!("  {label}")));
    }
    if items.is_empty() {
        items.push(ListItem::new("  (no access records)"));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Access — {} ", path.display())),
        )
        .highlight_symbol("› ")
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default();
    if !app.access_targets().is_empty() {
        state.select(Some(app.access_selected));
    }
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let detail = if let Some(phrase) = &app.invitation_phrase {
        format!(
            "Invitation phrase ({} words): {}\nRecipient types every word on one line, with spaces, then presses <Enter> once.",
            phrase.split_whitespace().count(),
            phrase.as_str()
        )
    } else {
        match &app.mode {
            Mode::InviteDuration { buffer } => {
                format!("Duration in minutes: {buffer}_ — <Enter> defaults to 30")
            }
            Mode::InviteWords { buffer, .. } => {
                format!("Phrase words: {buffer}_ — 4–6; <Enter> defaults to 4")
            }
            Mode::RecipientName { buffer, .. } => format!("Friendly name: {buffer}_"),
            Mode::ConfirmApprove { request_id } => format!(
                "Approve request {}? Verify the friendly name and fingerprint out of band.",
                hex::encode_upper(&request_id[..4])
            ),
            Mode::ConfirmReject { request_id } => format!(
                "Reject and remove request {}?",
                hex::encode_upper(&request_id[..4])
            ),
            Mode::ConfirmClose { invitation_id } => format!(
                "Close invitation {}?",
                hex::encode_upper(&invitation_id[..4])
            ),
            Mode::ConfirmRemoveRecipient { age_recipient } => app
                .vault
                .recipients()
                .iter()
                .find(|recipient| &recipient.age_recipient == age_recipient)
                .map(|recipient| {
                    format!(
                        "Remove {} [{}]? Old Git versions remain accessible to this key.",
                        recipient.name,
                        recipient.fingerprint()
                    )
                })
                .unwrap_or_else(|| "Recipient no longer exists".into()),
            _ => match app.selected_access_target() {
                Some(AccessTarget::Recipient(index)) => {
                    let recipient = &app.vault.recipients()[index];
                    format!(
                        "{}\n{}:{}  age: {}",
                        recipient.name,
                        recipient.backend,
                        recipient.locator,
                        recipient.age_recipient
                    )
                }
                Some(AccessTarget::Invitation(id)) => app
                    .vault
                    .invitations()
                    .iter()
                    .find(|invitation| invitation.id == id)
                    .map(invitation_detail)
                    .unwrap_or_default(),
                Some(AccessTarget::Request(id)) => app
                    .requests
                    .iter()
                    .find(|request| request.id == id)
                    .map(|request| {
                        request
                            .claim
                            .as_ref()
                            .map(|claim| {
                                format!(
                                    "Requested name: {}\n{}:{}; invitation {}",
                                    claim.recipient.name,
                                    claim.recipient.backend,
                                    claim.recipient.locator,
                                    hex::encode_upper(&claim.invitation_id[..4])
                                )
                            })
                            .unwrap_or_else(|| {
                                request
                                    .error
                                    .clone()
                                    .unwrap_or_else(|| "Unreadable request".into())
                            })
                    })
                    .unwrap_or_default(),
                None => "Press n to open an invitation slot".into(),
            },
        }
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Details "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    draw_footer(frame, app, chunks[2], chunks[3]);
}

fn invitation_detail(invitation: &Invitation) -> String {
    format!(
        "Invitation {}\nExpires at Unix {}; {} attempt(s) remain",
        hex::encode_upper(&invitation.id[..4]),
        invitation.expires_at,
        invitation.attempts_remaining
    )
}

fn draw_footer(
    frame: &mut Frame,
    app: &App,
    status_area: ratatui::layout::Rect,
    keys_area: ratatui::layout::Rect,
) {
    frame.render_widget(
        Paragraph::new(format!(" {}", app.status))
            .block(Block::default().borders(Borders::ALL).title(" Status ")),
        status_area,
    );
    frame.render_widget(
        Paragraph::new(format!(" {}", app_key_help(&app.mode)))
            .block(Block::default().borders(Borders::ALL).title(" Keys ")),
        keys_area,
    );
}

fn app_key_help(mode: &Mode) -> &'static str {
    match mode {
        Mode::List => {
            "<j>/<k> select  <n> new  <e> edit  <d> delete  <r> reveal  <y> output  <a> access  <q> quit"
        }
        Mode::Name { .. } => "<Enter> continue  <Backspace> edit  <Esc> cancel",
        Mode::Value { .. } => "<Enter> save  <Backspace> edit  <Esc> cancel",
        Mode::ConfirmDelete { .. } => "<y>/<Enter> confirm  <n>/<Esc> cancel",
        Mode::Access => {
            "<j>/<k> select  <n> invite  <e> rename  <d> remove  <a> approve  <x> reject  <c> close  <q> back"
        }
        Mode::InviteDuration { .. } => "<Enter> continue  <Backspace> edit  <Esc> cancel",
        Mode::InviteWords { .. } => "<Enter> create  <Backspace> edit  <Esc> cancel",
        Mode::RecipientName { .. } => "<Enter> rename  <Backspace> edit  <Esc> cancel",
        Mode::ConfirmApprove { .. }
        | Mode::ConfirmReject { .. }
        | Mode::ConfirmClose { .. }
        | Mode::ConfirmRemoveRecipient { .. } => "<y>/<Enter> confirm  <n>/<Esc> cancel",
    }
}

pub enum RequesterEffect {
    None,
    Submit {
        invitation: PublicInvitation,
        phrase: String,
        name: String,
    },
    Quit,
}

#[derive(Debug)]
enum RequesterMode {
    List,
    Phrase { buffer: String },
    Name { phrase: String, buffer: String },
    Confirm { phrase: String, name: String },
}

pub struct RequesterApp {
    invitations: Vec<PublicInvitation>,
    selected: usize,
    mode: RequesterMode,
    status: String,
}

impl RequesterApp {
    pub fn new(invitations: Vec<PublicInvitation>) -> Self {
        Self {
            invitations,
            selected: 0,
            mode: RequesterMode::List,
            status: "Ready".into(),
        }
    }

    pub fn input(&mut self, key: InputKey) -> RequesterEffect {
        match &mut self.mode {
            RequesterMode::List => match key {
                InputKey::Down | InputKey::Char('j') => {
                    if !self.invitations.is_empty() {
                        self.selected = (self.selected + 1).min(self.invitations.len() - 1);
                    }
                    RequesterEffect::None
                }
                InputKey::Up | InputKey::Char('k') => {
                    self.selected = self.selected.saturating_sub(1);
                    RequesterEffect::None
                }
                InputKey::Char('r') | InputKey::Enter => {
                    if self.invitations.is_empty() {
                        self.status = "There are no open invitation slots".into();
                    } else if self.invitations[self.selected].is_expired() {
                        self.status = "That invitation has expired".into();
                    } else {
                        self.mode = RequesterMode::Phrase {
                            buffer: String::new(),
                        };
                        self.status.clear();
                    }
                    RequesterEffect::None
                }
                InputKey::Char('q') | InputKey::Esc => RequesterEffect::Quit,
                _ => RequesterEffect::None,
            },
            RequesterMode::Phrase { buffer } => match key {
                InputKey::Esc => {
                    buffer.zeroize();
                    self.mode = RequesterMode::List;
                    self.status = "Request cancelled".into();
                    RequesterEffect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    RequesterEffect::None
                }
                InputKey::Enter => {
                    let phrase = buffer.trim();
                    if phrase.is_empty() {
                        self.status = "Invitation phrase cannot be empty".into();
                    } else if validate_invitation_phrase(phrase).is_err() {
                        self.status =
                            "Invalid phrase: use 4–6 BIP-39 words on one line, separated by spaces"
                                .into();
                    } else {
                        let phrase = phrase.to_owned();
                        buffer.zeroize();
                        self.mode = RequesterMode::Name {
                            phrase,
                            buffer: String::new(),
                        };
                        self.status.clear();
                    }
                    RequesterEffect::None
                }
                InputKey::Char(character) => {
                    if buffer.len() < 128 {
                        buffer.push(character);
                    }
                    RequesterEffect::None
                }
                _ => RequesterEffect::None,
            },
            RequesterMode::Name { phrase, buffer } => match key {
                InputKey::Esc => {
                    phrase.zeroize();
                    buffer.zeroize();
                    self.mode = RequesterMode::List;
                    self.status = "Request cancelled".into();
                    RequesterEffect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    RequesterEffect::None
                }
                InputKey::Enter => {
                    let name = buffer.trim().to_owned();
                    if name.is_empty() {
                        self.status = "Friendly name cannot be empty".into();
                    } else if name.len() > MAX_FRIENDLY_NAME {
                        self.status = "Friendly name is too long".into();
                    } else {
                        let secret = std::mem::take(phrase);
                        buffer.zeroize();
                        self.mode = RequesterMode::Confirm {
                            phrase: secret,
                            name,
                        };
                        self.status.clear();
                    }
                    RequesterEffect::None
                }
                InputKey::Char(character) => {
                    if buffer.len() + character.len_utf8() <= MAX_FRIENDLY_NAME {
                        buffer.push(character);
                    }
                    RequesterEffect::None
                }
                _ => RequesterEffect::None,
            },
            RequesterMode::Confirm { phrase, name } => match key {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let invitation = self.invitations[self.selected].clone();
                    let phrase = std::mem::take(phrase);
                    let name = std::mem::take(name);
                    self.mode = RequesterMode::List;
                    RequesterEffect::Submit {
                        invitation,
                        phrase,
                        name,
                    }
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    phrase.zeroize();
                    name.zeroize();
                    self.mode = RequesterMode::List;
                    self.status = "Request cancelled".into();
                    RequesterEffect::None
                }
                _ => RequesterEffect::None,
            },
        }
    }
}

impl Drop for RequesterApp {
    fn drop(&mut self) {
        match &mut self.mode {
            RequesterMode::Phrase { buffer } => buffer.zeroize(),
            RequesterMode::Name { phrase, buffer } => {
                phrase.zeroize();
                buffer.zeroize();
            }
            RequesterMode::Confirm { phrase, name } => {
                phrase.zeroize();
                name.zeroize();
            }
            RequesterMode::List => {}
        }
    }
}

pub fn draw_requester(frame: &mut Frame, app: &RequesterApp, path: &Path) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let items = if app.invitations.is_empty() {
        vec![ListItem::new("  (no open invitation slots)")]
    } else {
        app.invitations
            .iter()
            .map(|invitation| {
                ListItem::new(format!(
                    "  Invitation {}  expires {}{}",
                    invitation.short_id(),
                    invitation.expires_at,
                    if invitation.is_expired() {
                        " (expired)"
                    } else {
                        ""
                    }
                ))
            })
            .collect()
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Request access — {} ", path.display())),
        )
        .highlight_symbol("› ")
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default();
    if !app.invitations.is_empty() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, chunks[0], &mut state);
    let detail = match &app.mode {
        RequesterMode::List => "Select the invitation shared with you".into(),
        RequesterMode::Phrase { buffer } => {
            format!("Invitation phrase: {buffer}_\nEnter the 4–6 words separated by spaces.")
        }
        RequesterMode::Name { buffer, .. } => format!("Friendly name: {buffer}_"),
        RequesterMode::Confirm { name, .. } => {
            format!("Request access as {name}? The request will be committed with this vault.")
        }
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Request "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(format!(" {}", app.status))
            .block(Block::default().borders(Borders::ALL).title(" Status ")),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(format!(" {}", requester_key_help(&app.mode)))
            .block(Block::default().borders(Borders::ALL).title(" Keys ")),
        chunks[3],
    );
}

fn requester_key_help(mode: &RequesterMode) -> &'static str {
    match mode {
        RequesterMode::List => "<j>/<k> select  <r>/<Enter> request access  <q>/<Esc> quit",
        RequesterMode::Phrase { .. } | RequesterMode::Name { .. } => {
            "<Enter> continue  <Backspace> edit  <Esc> cancel"
        }
        RequesterMode::Confirm { .. } => "<y>/<Enter> confirm  <n>/<Esc> cancel",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::new(crate::identity::AuthorizedRecipient {
            name: "Primary".into(),
            backend: "test".into(),
            locator: "1".into(),
            age_recipient: "age1test".into(),
        })
    }

    fn press(app: &mut App, keys: &str) -> Vec<Effect> {
        keys.chars()
            .map(|key| app.input(InputKey::Char(key)))
            .collect()
    }

    #[test]
    fn create_reveal_output_and_delete() {
        let mut app = App::new(vault(), Vec::new());
        app.input(InputKey::Char('n'));
        press(&mut app, "TOKEN");
        app.input(InputKey::Enter);
        press(&mut app, "secret");
        assert!(matches!(app.input(InputKey::Enter), Effect::Changed));
        assert_eq!(app.vault().get("TOKEN"), Some("secret"));
        assert!(
            matches!(app.input(InputKey::Char('y')), Effect::Output(value) if value == "secret")
        );
        app.input(InputKey::Char('d'));
        assert!(matches!(app.input(InputKey::Char('y')), Effect::Changed));
        assert!(app.vault().get("TOKEN").is_none());
    }

    #[test]
    fn invitation_defaults_are_programmable() {
        let mut app = App::new(vault(), Vec::new());
        app.input(InputKey::Char('a'));
        app.input(InputKey::Char('n'));
        app.input(InputKey::Enter);
        assert!(matches!(
            app.input(InputKey::Enter),
            Effect::CreateInvitation {
                minutes: 30,
                words: 4
            }
        ));
    }

    #[test]
    fn requester_enters_all_phrase_words_before_enter() {
        let invitation = PublicInvitation {
            id: [3; 16],
            expires_at: crate::crypto::now_unix() + 60,
            binding_mac: [4; 32],
        };
        let mut app = RequesterApp::new(vec![invitation]);
        app.input(InputKey::Char('r'));
        for character in "abandon ability able about".chars() {
            app.input(InputKey::Char(character));
        }
        app.input(InputKey::Enter);
        assert!(matches!(app.mode, RequesterMode::Name { .. }));
    }
}
