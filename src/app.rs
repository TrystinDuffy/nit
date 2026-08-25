use std::path::Path;

use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use zeroize::Zeroize;

use crate::{crypto::Vault, keys::InputKey};

const MAX_NAME_LEN: usize = 1_024;
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum Effect {
    None,
    Changed,
    Output(String),
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
}

pub struct App {
    vault: Vault,
    selected: usize,
    revealed: Option<String>,
    mode: Mode,
    status: String,
}

impl App {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            selected: 0,
            revealed: None,
            mode: Mode::List,
            status: "n new  e edit  d delete  r reveal  y output  q quit".into(),
        }
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    pub fn cancel(&mut self) {
        let old = std::mem::replace(&mut self.mode, Mode::List);
        zeroize_mode(old);
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
                        self.status = "Enter the secret value; Enter saves, Esc cancels".into();
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
                self.status = "Enter a new secret name; Enter continues, Esc cancels".into();
                Effect::None
            }
            InputKey::Char('e') => {
                if let Some(name) = self.selected_name().map(str::to_owned) {
                    self.mode = Mode::Value {
                        name,
                        buffer: String::new(),
                        editing: true,
                    };
                    self.status = "Enter the replacement value; Enter saves, Esc cancels".into();
                } else {
                    self.status = "The vault has no secrets to edit".into();
                }
                Effect::None
            }
            InputKey::Char('d') => {
                if let Some(name) = self.selected_name().map(str::to_owned) {
                    self.mode = Mode::ConfirmDelete { name };
                    self.status = "Delete this secret? y/Enter confirms, n/Esc cancels".into();
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
            InputKey::Char('q') | InputKey::Esc => Effect::Quit,
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
}

impl Drop for App {
    fn drop(&mut self) {
        let mode = std::mem::replace(&mut self.mode, Mode::List);
        zeroize_mode(mode);
    }
}

fn zeroize_mode(mut mode: Mode) {
    match &mut mode {
        Mode::Name { buffer } => buffer.zeroize(),
        Mode::Value { name, buffer, .. } => {
            name.zeroize();
            buffer.zeroize();
        }
        Mode::ConfirmDelete { name } => name.zeroize(),
        Mode::List => {}
    }
}

pub fn draw(frame: &mut Frame, app: &App, path: &Path) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(4),
            Constraint::Length(3),
        ])
        .split(area);

    let title = format!(" {} ", path.display());
    let items: Vec<ListItem> = app
        .vault
        .names()
        .map(|name| ListItem::new(format!("  {name}")))
        .collect();
    let list = if items.is_empty() {
        List::new(vec![ListItem::new(
            "  (empty — press n to create a secret)",
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
                    "••••••••  (press r to reveal)".into()
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
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Secret "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    let help = Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::raw(&app.status),
    ]);
    frame.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(" Keys ")),
        chunks[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(app: &mut App, keys: &str) -> Vec<Effect> {
        keys.chars()
            .map(|key| app.input(InputKey::Char(key)))
            .collect()
    }

    #[test]
    fn create_reveal_output_and_delete() {
        let mut app = App::new(Vault::default());
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
}
