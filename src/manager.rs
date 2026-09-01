use anyhow::Result;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::{
    git::{validate_vault_name, GitRepository},
    terminal::{event_to_input, require_terminal, with_terminal, InputKey},
};

const MAX_VAULT_NAME_LEN: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagerAction {
    Open(String),
    Create(String),
}

enum Mode {
    Browse,
    NewVault { buffer: String },
    ConfirmNuke { vault: String },
}

struct ManagerUi {
    vaults: Vec<String>,
    selected: usize,
    mode: Mode,
    status: String,
}

impl ManagerUi {
    fn new(vaults: Vec<String>) -> Self {
        let status = if vaults.is_empty() {
            "No vaults in this repository; press <n> to create one".into()
        } else {
            "Select a vault to open, create another, or nuke a local vault".into()
        };
        Self {
            vaults,
            selected: 0,
            mode: Mode::Browse,
            status,
        }
    }

    fn draw(&self, frame: &mut Frame, repository: &GitRepository) {
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(frame.area());
        let items = if self.vaults.is_empty() {
            vec![ListItem::new("  (no vaults)")]
        } else {
            self.vaults
                .iter()
                .map(|vault| ListItem::new(format!("  {vault}  refs/vaults/{vault}")))
                .collect()
        };
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" git vault — {} ", repository.workdir().display())),
            )
            .highlight_symbol("› ")
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default();
        if !self.vaults.is_empty() {
            state.select(Some(self.selected));
        }
        frame.render_stateful_widget(list, areas[0], &mut state);
        let status = match &self.mode {
            Mode::NewVault { buffer } => format!(" New vault name: {buffer}_"),
            Mode::ConfirmNuke { vault } => format!(
                " Nuke local vault {vault:?}? Remote copies remain; unreachable Git objects may remain until GC."
            ),
            Mode::Browse => format!(" {}", self.status),
        };
        frame.render_widget(
            Paragraph::new(status).block(Block::default().borders(Borders::ALL).title(" Status ")),
            areas[1],
        );
        frame.render_widget(
            Paragraph::new(format!(" {}", self.key_help()))
                .block(Block::default().borders(Borders::ALL).title(" Keys ")),
            areas[2],
        );
    }

    fn key_help(&self) -> &'static str {
        match self.mode {
            Mode::Browse => "<j>/<k> select  <Enter> open  <n> new  <d> nuke local  <q>/<Esc> quit",
            Mode::NewVault { .. } => "<Enter> create  <Backspace> edit  <Esc> cancel",
            Mode::ConfirmNuke { .. } => "<y>/<Enter> nuke  <n>/<Esc> cancel",
        }
    }

    fn selected_vault(&self) -> Option<&str> {
        self.vaults.get(self.selected).map(String::as_str)
    }
}

pub fn run(repository: &GitRepository) -> Result<Option<ManagerAction>> {
    require_terminal()?;
    let mut app = ManagerUi::new(repository.list_vaults()?);
    with_terminal(|terminal| loop {
        terminal.draw(|frame| app.draw(frame, repository))?;
        let Some(input) = event_to_input()? else {
            continue;
        };
        match &mut app.mode {
            Mode::Browse => match input {
                InputKey::Down | InputKey::Char('j') if !app.vaults.is_empty() => {
                    app.selected = (app.selected + 1).min(app.vaults.len() - 1);
                }
                InputKey::Up | InputKey::Char('k') => {
                    app.selected = app.selected.saturating_sub(1);
                }
                InputKey::Enter | InputKey::Char('o') => {
                    if let Some(vault) = app.selected_vault() {
                        break Ok(Some(ManagerAction::Open(vault.to_owned())));
                    }
                    app.status = "There is no vault to open; press <n> to create one".into();
                }
                InputKey::Char('n') => {
                    app.mode = Mode::NewVault {
                        buffer: String::new(),
                    };
                }
                InputKey::Char('d') => {
                    if let Some(vault) = app.selected_vault().map(str::to_owned) {
                        app.mode = Mode::ConfirmNuke { vault };
                    } else {
                        app.status = "There is no local vault to nuke".into();
                    }
                }
                InputKey::Char('q') | InputKey::Esc => break Ok(None),
                _ => {}
            },
            Mode::NewVault { buffer } => match input {
                InputKey::Char(character)
                    if buffer.len() + character.len_utf8() <= MAX_VAULT_NAME_LEN =>
                {
                    buffer.push(character);
                }
                InputKey::Backspace => {
                    buffer.pop();
                }
                InputKey::Enter => {
                    let name = buffer.trim().to_owned();
                    match validate_vault_name(&name) {
                        Ok(()) if app.vaults.iter().any(|vault| vault == &name) => {
                            app.status = format!("Vault {name:?} already exists");
                            app.mode = Mode::Browse;
                        }
                        Ok(()) => break Ok(Some(ManagerAction::Create(name))),
                        Err(error) => {
                            app.status = error.to_string();
                            app.mode = Mode::Browse;
                        }
                    }
                }
                InputKey::Esc => {
                    app.mode = Mode::Browse;
                    app.status = "Vault creation cancelled".into();
                }
                _ => {}
            },
            Mode::ConfirmNuke { vault } => match input {
                InputKey::Enter | InputKey::Char('y') | InputKey::Char('Y') => {
                    let vault = vault.clone();
                    let deleted = repository.delete_vault(&vault)?;
                    app.vaults = repository.list_vaults()?;
                    app.selected = app.selected.min(app.vaults.len().saturating_sub(1));
                    app.mode = Mode::Browse;
                    app.status = if deleted == 0 {
                        format!("Vault {vault:?} was already absent")
                    } else {
                        format!(
                            "Nuked {deleted} local ref(s) for {vault:?}; remote copies were not changed"
                        )
                    };
                }
                InputKey::Char('n') | InputKey::Char('N') | InputKey::Esc => {
                    app.mode = Mode::Browse;
                    app.status = "Vault nuke cancelled".into();
                }
                _ => {}
            },
        }
    })
}
