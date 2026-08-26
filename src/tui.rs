use std::{collections::BTreeMap, path::Path};

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use zeroize::Zeroize;

use crate::{
    crypto::VaultValue,
    event::EpochMember,
    keys::InputKey,
    state::{InvitationState, PendingProposal},
};

const MAX_KEY_LEN: usize = 1_024;
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum Effect {
    None,
    Put { key: String, value: VaultValue },
    Delete { key: String },
    RemoveMember { signing_public_key: [u8; 32] },
    CreateInvitation,
    CloseInvitation { invitation_id: [u8; 16] },
    RespondProposal { proposal_event_hash: [u8; 32] },
    ApproveProposal { proposal_event_hash: [u8; 32] },
    Output(String),
    Quit,
}

#[derive(Debug)]
enum Mode {
    Secrets,
    NewKey {
        buffer: String,
    },
    Value {
        key: String,
        buffer: String,
    },
    ConfirmDelete {
        key: String,
    },
    Access,
    ConfirmRemoveMember {
        signing_public_key: [u8; 32],
        name: String,
    },
}

pub struct VaultUi {
    values: BTreeMap<String, VaultValue>,
    members: Vec<EpochMember>,
    invitations: Vec<InvitationState>,
    proposals: Vec<PendingProposal>,
    mode: Mode,
    selected: usize,
    access_selected: usize,
    revealed: Option<String>,
    status: String,
}

impl VaultUi {
    pub fn new(
        values: BTreeMap<String, VaultValue>,
        members: Vec<EpochMember>,
        invitations: Vec<InvitationState>,
        proposals: Vec<PendingProposal>,
    ) -> Self {
        Self {
            values,
            members,
            invitations,
            proposals: visible_proposals(proposals),
            mode: Mode::Secrets,
            selected: 0,
            access_selected: 0,
            revealed: None,
            status: "Verified trusted state".into(),
        }
    }

    pub fn input(&mut self, input: InputKey) -> Effect {
        match &mut self.mode {
            Mode::Secrets => self.input_secrets(input),
            Mode::NewKey { buffer } => match input {
                InputKey::Esc => {
                    buffer.zeroize();
                    self.mode = Mode::Secrets;
                    self.status = "Creation cancelled".into();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let name = buffer.trim().to_owned();
                    if name.is_empty() {
                        self.status = "Secret name cannot be empty".into();
                    } else if self.values.contains_key(&name) {
                        self.status = format!("Secret {name:?} already exists");
                    } else {
                        buffer.zeroize();
                        self.mode = Mode::Value {
                            key: name,
                            buffer: String::new(),
                        };
                        self.status.clear();
                    }
                    Effect::None
                }
                InputKey::Char(character) if buffer.len() + character.len_utf8() <= MAX_KEY_LEN => {
                    buffer.push(character);
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::Value { key, buffer } => match input {
                InputKey::Esc => {
                    key.zeroize();
                    buffer.zeroize();
                    self.mode = Mode::Secrets;
                    self.status = "Edit cancelled".into();
                    Effect::None
                }
                InputKey::Backspace => {
                    buffer.pop();
                    Effect::None
                }
                InputKey::Enter => {
                    let key = std::mem::take(key);
                    let value = std::mem::take(buffer);
                    self.mode = Mode::Secrets;
                    Effect::Put {
                        key,
                        value: VaultValue::Text(value),
                    }
                }
                InputKey::Char(character)
                    if buffer.len() + character.len_utf8() <= MAX_VALUE_LEN =>
                {
                    buffer.push(character);
                    Effect::None
                }
                InputKey::Tab if buffer.len() < MAX_VALUE_LEN => {
                    buffer.push('\t');
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::ConfirmDelete { key } => match input {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let key = std::mem::take(key);
                    self.mode = Mode::Secrets;
                    Effect::Delete { key }
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    key.zeroize();
                    self.mode = Mode::Secrets;
                    self.status = "Deletion cancelled".into();
                    Effect::None
                }
                _ => Effect::None,
            },
            Mode::Access => self.input_access(input),
            Mode::ConfirmRemoveMember {
                signing_public_key,
                name,
            } => match input {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let signing_public_key = *signing_public_key;
                    name.zeroize();
                    self.mode = Mode::Access;
                    Effect::RemoveMember { signing_public_key }
                }
                InputKey::Esc | InputKey::Char('n') | InputKey::Char('N') => {
                    name.zeroize();
                    self.mode = Mode::Access;
                    self.status = "Member removal cancelled".into();
                    Effect::None
                }
                _ => Effect::None,
            },
        }
    }

    pub fn apply_put(&mut self, key: String, value: VaultValue) {
        self.values.insert(key.clone(), value);
        self.selected = self
            .values
            .keys()
            .position(|name| name == &key)
            .unwrap_or(0);
        self.revealed = None;
        self.status = format!("Appended trusted Put for {key}");
    }

    pub fn apply_delete(&mut self, key: &str) {
        self.values.remove(key);
        self.selected = self.selected.min(self.values.len().saturating_sub(1));
        self.revealed = None;
        self.status = format!("Appended trusted Delete for {key}");
    }

    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status.zeroize();
        self.status = message.into();
    }

    pub fn refresh_access(
        &mut self,
        members: Vec<EpochMember>,
        invitations: Vec<InvitationState>,
        proposals: Vec<PendingProposal>,
    ) {
        self.members = members;
        self.invitations = invitations;
        self.proposals = visible_proposals(proposals);
        self.access_selected = self
            .access_selected
            .min(self.access_count().saturating_sub(1));
    }

    pub fn draw(&self, frame: &mut Frame, repository: &Path, vault: &str) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),
                Constraint::Length(5),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(frame.area());
        if matches!(self.mode, Mode::Access | Mode::ConfirmRemoveMember { .. }) {
            self.draw_access(frame, repository, vault, &chunks);
        } else {
            self.draw_secrets(frame, repository, vault, &chunks);
        }
        frame.render_widget(
            Paragraph::new(format!(" {}", self.status))
                .block(Block::default().borders(Borders::ALL).title(" Status ")),
            chunks[2],
        );
        frame.render_widget(
            Paragraph::new(format!(" {}", key_help(&self.mode)))
                .block(Block::default().borders(Borders::ALL).title(" Keys ")),
            chunks[3],
        );
    }

    fn input_secrets(&mut self, key: InputKey) -> Effect {
        match key {
            InputKey::Down | InputKey::Char('j') => {
                if !self.values.is_empty() {
                    self.selected = (self.selected + 1).min(self.values.len() - 1);
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
                self.mode = Mode::NewKey {
                    buffer: String::new(),
                };
                self.status.clear();
                Effect::None
            }
            InputKey::Char('e') => {
                if let Some(key) = self.selected_key().map(str::to_owned) {
                    self.mode = Mode::Value {
                        key,
                        buffer: String::new(),
                    };
                    self.status.clear();
                } else {
                    self.status = "The vault has no secrets to edit".into();
                }
                Effect::None
            }
            InputKey::Char('d') => {
                if let Some(key) = self.selected_key().map(str::to_owned) {
                    self.mode = Mode::ConfirmDelete { key };
                    self.status.clear();
                } else {
                    self.status = "The vault has no secrets to delete".into();
                }
                Effect::None
            }
            InputKey::Char('r') => {
                if let Some(key) = self.selected_key().map(str::to_owned) {
                    self.revealed = if self.revealed.as_deref() == Some(&key) {
                        None
                    } else {
                        Some(key)
                    };
                }
                Effect::None
            }
            InputKey::Char('y') => {
                if let Some(value) = self
                    .selected_key()
                    .and_then(|key| self.values.get(key))
                    .map(VaultValue::display)
                {
                    Effect::Output(value)
                } else {
                    self.status = "The vault has no selected value".into();
                    Effect::None
                }
            }
            InputKey::Char('a') => {
                self.mode = Mode::Access;
                self.revealed = None;
                self.status = "Access changes stay inert until the owner admits them".into();
                Effect::None
            }
            InputKey::Char('q') | InputKey::Esc => Effect::Quit,
            _ => Effect::None,
        }
    }

    fn input_access(&mut self, key: InputKey) -> Effect {
        match key {
            InputKey::Down | InputKey::Char('j') => {
                let count = self.access_count();
                if count > 0 {
                    self.access_selected = (self.access_selected + 1).min(count - 1);
                }
                Effect::None
            }
            InputKey::Up | InputKey::Char('k') => {
                self.access_selected = self.access_selected.saturating_sub(1);
                Effect::None
            }
            InputKey::Char('n') => Effect::CreateInvitation,
            InputKey::Char('d') => {
                let Some(member) = self.members.get(self.access_selected) else {
                    self.status = "Select a trusted member to remove".into();
                    return Effect::None;
                };
                if self.members.len() <= 1 {
                    self.status = "The final member cannot be removed".into();
                } else if member.role == crate::event::Role::Owner
                    && self
                        .members
                        .iter()
                        .filter(|item| item.role == crate::event::Role::Owner)
                        .count()
                        <= 1
                {
                    self.status = "The final owner cannot be removed".into();
                } else {
                    self.mode = Mode::ConfirmRemoveMember {
                        signing_public_key: member.identity.signing_public_key,
                        name: member.identity.name.clone(),
                    };
                    self.status.clear();
                }
                Effect::None
            }
            InputKey::Char('s') => {
                let Some(proposal) = self.selected_proposal() else {
                    self.status = "Select a new join request to send its challenge".into();
                    return Effect::None;
                };
                if proposal.response_event_hash.is_some() {
                    self.status = "Phrase proof is complete; press <a> to admit this member".into();
                    Effect::None
                } else if proposal.owner_response_event_hash.is_some() {
                    self.status = format!(
                        "Challenge already sent; reopen with {}'s requesting key to finish the phrase proof",
                        proposal.identity.name
                    );
                    Effect::None
                } else {
                    Effect::RespondProposal {
                        proposal_event_hash: proposal.event_hash,
                    }
                }
            }
            InputKey::Char('a') => {
                let Some(proposal) = self.selected_proposal() else {
                    self.status = "Select a completed phrase proof to admit".into();
                    return Effect::None;
                };
                if proposal.response_event_hash.is_none() {
                    self.status = "Phrase proof is not complete yet".into();
                    Effect::None
                } else {
                    Effect::ApproveProposal {
                        proposal_event_hash: proposal.event_hash,
                    }
                }
            }
            InputKey::Char('c') => {
                let Some(invitation) = self.selected_invitation() else {
                    self.status = "Select an invitation to close".into();
                    return Effect::None;
                };
                Effect::CloseInvitation {
                    invitation_id: invitation.invitation_id,
                }
            }
            InputKey::Char('e') => {
                self.status = "Use `git vault <name> set-role` to change a member role".into();
                Effect::None
            }
            InputKey::Char('q') | InputKey::Esc => {
                self.mode = Mode::Secrets;
                self.status = "Verified trusted state".into();
                Effect::None
            }
            _ => Effect::None,
        }
    }

    fn selected_key(&self) -> Option<&str> {
        self.values.keys().nth(self.selected).map(String::as_str)
    }

    fn selected_invitation(&self) -> Option<&InvitationState> {
        self.access_selected
            .checked_sub(self.members.len())
            .and_then(|index| self.invitations.get(index))
    }

    fn selected_proposal(&self) -> Option<&PendingProposal> {
        self.access_selected
            .checked_sub(self.members.len() + self.invitations.len())
            .and_then(|index| self.proposals.get(index))
    }

    fn access_count(&self) -> usize {
        self.members.len() + self.invitations.len() + self.proposals.len()
    }

    fn access_detail(&self) -> String {
        if let Some(proposal) = self.selected_proposal() {
            if proposal.response_event_hash.is_some() {
                return "The requester proved the invitation phrase. Press <a> to admit this member."
                    .into();
            }
            if proposal.owner_response_event_hash.is_some() {
                return format!(
                    "Challenge sent. Reopen with {}'s requesting YubiKey to finish the phrase proof.",
                    proposal.identity.name
                );
            }
            return "New join request. Press <s> to send the requester a PAKE challenge.".into();
        }
        if self.selected_invitation().is_some() {
            return "Invitation is open. The requester selects it and enters its four-word phrase."
                .into();
        }
        "Trusted members, active invitations, and join requests".into()
    }

    fn draw_secrets(
        &self,
        frame: &mut Frame,
        repository: &Path,
        vault: &str,
        chunks: &[ratatui::layout::Rect],
    ) {
        let items = if self.values.is_empty() {
            vec![ListItem::new("  (empty — press <n> to create a secret)")]
        } else {
            self.values
                .keys()
                .map(|key| ListItem::new(format!("  {key}")))
                .collect()
        };
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" git vault {vault} — {} ", repository.display())),
            )
            .highlight_symbol("› ")
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default();
        if !self.values.is_empty() {
            state.select(Some(self.selected));
        }
        frame.render_stateful_widget(list, chunks[0], &mut state);
        let detail = match &self.mode {
            Mode::Secrets => self
                .selected_key()
                .map(|key| {
                    if self.revealed.as_deref() == Some(key) {
                        self.values.get(key).unwrap().display()
                    } else {
                        "••••••••  (press <r> to reveal)".into()
                    }
                })
                .unwrap_or_else(|| "No secrets".into()),
            Mode::NewKey { buffer } => format!("Secret name: {buffer}_"),
            Mode::Value { key, buffer } => {
                format!(
                    "Value for {key}: {}_",
                    "•".repeat(buffer.chars().count().min(64))
                )
            }
            Mode::ConfirmDelete { key } => format!("Permanently delete {key}?"),
            Mode::Access | Mode::ConfirmRemoveMember { .. } => unreachable!(),
        };
        frame.render_widget(
            Paragraph::new(detail)
                .block(Block::default().borders(Borders::ALL).title(" Secret "))
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    }

    fn draw_access(
        &self,
        frame: &mut Frame,
        repository: &Path,
        vault: &str,
        chunks: &[ratatui::layout::Rect],
    ) {
        let mut items = Vec::new();
        for member in &self.members {
            items.push(ListItem::new(format!(
                "  trusted member  {}  {:?}  {}",
                member.identity.name,
                member.role,
                member.identity.fingerprint()
            )));
        }
        for invitation in &self.invitations {
            items.push(ListItem::new(format!(
                "  active invitation  {}  expires {}",
                hex::encode_upper(&invitation.invitation_id[..4]),
                invitation.expires_at
            )));
        }
        for proposal in &self.proposals {
            let stage = if proposal.response_event_hash.is_some() {
                "phrase proof complete — ready to admit"
            } else if proposal.owner_response_event_hash.is_some() {
                "challenge sent — requester must finish"
            } else {
                "new — owner must send challenge"
            };
            items.push(ListItem::new(format!(
                "  join request  {}  {}  {}  {:?}",
                hex::encode_upper(&proposal.event_hash[..4]),
                proposal.identity.name,
                stage,
                proposal.validation
            )));
        }
        if items.is_empty() {
            items.push(ListItem::new("  (no access records)"));
        }
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                " Access — git vault {vault} — {} ",
                repository.display()
            )))
            .highlight_symbol("› ")
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default();
        if self.access_count() > 0 {
            state.select(Some(self.access_selected));
        }
        frame.render_stateful_widget(list, chunks[0], &mut state);
        let detail = match &self.mode {
            Mode::ConfirmRemoveMember { name, .. } => {
                format!("Remove {name}, rotate the epoch key, and invalidate invitations?")
            }
            _ => self.access_detail(),
        };
        frame.render_widget(
            Paragraph::new(detail).block(Block::default().borders(Borders::ALL).title(" Details ")),
            chunks[1],
        );
    }
}

fn visible_proposals(proposals: Vec<PendingProposal>) -> Vec<PendingProposal> {
    let finalized_responses = proposals
        .iter()
        .filter_map(|proposal| proposal.response_event_hash)
        .collect::<Vec<_>>();
    proposals
        .into_iter()
        .filter(|proposal| {
            proposal.response_event_hash.is_some()
                || !proposal
                    .owner_response_event_hash
                    .is_some_and(|response| finalized_responses.contains(&response))
        })
        .collect()
}

impl Drop for VaultUi {
    fn drop(&mut self) {
        self.status.zeroize();
        match &mut self.mode {
            Mode::NewKey { buffer } => buffer.zeroize(),
            Mode::Value { key, buffer } => {
                key.zeroize();
                buffer.zeroize();
            }
            Mode::ConfirmDelete { key } => key.zeroize(),
            Mode::ConfirmRemoveMember { name, .. } => name.zeroize(),
            Mode::Secrets | Mode::Access => {}
        }
    }
}

fn key_help(mode: &Mode) -> &'static str {
    match mode {
        Mode::Secrets => {
            "<j>/<k> select  <n> new  <e> edit  <d> delete  <r> reveal  <y> output  <a> access  <q> quit"
        }
        Mode::NewKey { .. } => "<Enter> continue  <Backspace> edit  <Esc> cancel",
        Mode::Value { .. } => "<Enter> append  <Backspace> edit  <Esc> cancel",
        Mode::ConfirmDelete { .. } => "<y>/<Enter> confirm  <n>/<Esc> cancel",
        Mode::Access => {
            "<j>/<k> select  <n> invite  <s> send challenge  <a> admit  <c> close  <d> remove  <q>/<Esc> back"
        }
        Mode::ConfirmRemoveMember { .. } => "<y>/<Enter> confirm  <n>/<Esc> cancel",
    }
}
