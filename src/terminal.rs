use std::{
    fs::OpenOptions,
    io::{self, BufRead, BufReader, IsTerminal, Write},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use crossterm::{
    event::{self as terminal_event, Event as TerminalEvent, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};

use crate::{
    backends,
    identity::{DiscoveredIdentity, IdentityBackend, IdentityState},
    keys::InputKey,
};

pub fn identity_backend(id: &str) -> Result<Box<dyn IdentityBackend>> {
    identity_backends()
        .into_iter()
        .find(|backend| backend.id() == id)
        .with_context(|| format!("identity backend {id:?} is unavailable"))
}

pub fn discover_identities() -> Result<Vec<DiscoveredIdentity>> {
    let mut identities = Vec::new();
    for backend in identity_backends() {
        identities.extend(backend.discover()?);
    }
    identities.sort_by_key(DiscoveredIdentity::selector);
    Ok(identities)
}

pub fn choose_option(options: Vec<(String, String)>, purpose: &str) -> Result<String> {
    ensure!(!options.is_empty(), "there are no options to select");
    if options.len() == 1 {
        return Ok(options.into_iter().next().expect("length checked").0);
    }
    require_terminal()?;
    let mut selected = 0usize;
    let selected = with_terminal(|terminal| loop {
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(4), Constraint::Length(3)])
                .split(frame.area());
            let items = options
                .iter()
                .map(|(_, label)| ListItem::new(format!("  {label}")))
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
                selected = (selected + 1).min(options.len() - 1)
            }
            InputKey::Up | InputKey::Char('k') => selected = selected.saturating_sub(1),
            InputKey::Enter => break Ok(selected),
            InputKey::Esc | InputKey::Char('q') => bail!("selection cancelled"),
            _ => {}
        }
    })?;
    Ok(options[selected].0.clone())
}

pub fn choose_identity(
    identities: Vec<DiscoveredIdentity>,
    requested: Option<&str>,
    allow_provisionable: bool,
    include_unavailable: bool,
    purpose: &str,
) -> Result<DiscoveredIdentity> {
    let identities = identities
        .into_iter()
        .filter(|identity| {
            include_unavailable
                || allow_provisionable && identity.state.is_usable()
                || matches!(identity.state, IdentityState::Ready(_))
        })
        .collect::<Vec<_>>();
    if let Some(selector) = requested {
        let matches = identities
            .iter()
            .filter(|identity| {
                identity.selector().eq_ignore_ascii_case(selector)
                    || identity.locator.eq_ignore_ascii_case(selector)
            })
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [identity] => Ok((*identity).clone()),
            [] => bail!("identity {selector:?} was not discovered"),
            _ => bail!("identity selector {selector:?} is ambiguous; include its backend"),
        };
    }
    match identities.len() {
        0 => bail!("no usable identity was discovered"),
        1 => Ok(identities.into_iter().next().unwrap()),
        _ if !io::stdin().is_terminal() || !io::stdout().is_terminal() => bail!(
            "multiple identities were discovered; select one with --identity <backend:locator>"
        ),
        _ => choose_identity_tui(identities, purpose),
    }
}

pub fn event_to_input() -> Result<Option<InputKey>> {
    let TerminalEvent::Key(key) = terminal_event::read().context("cannot read terminal input")?
    else {
        return Ok(None);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(None);
    }
    Ok(match key.code {
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

pub fn discard_pending_input() -> Result<()> {
    while terminal_event::poll(Duration::ZERO).context("cannot poll terminal input")? {
        terminal_event::read().context("cannot discard pending terminal input")?;
    }
    Ok(())
}

pub fn prompt_line(prompt: &str) -> Result<String> {
    let mut writer = OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .context("cannot open the controlling terminal for output")?;
    writer
        .write_all(prompt.as_bytes())
        .context("cannot write terminal prompt")?;
    writer.flush().context("cannot flush terminal prompt")?;
    let reader = OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .context("cannot open the controlling terminal for input")?;
    let mut line = String::new();
    BufReader::new(reader)
        .read_line(&mut line)
        .context("cannot read terminal input")?;
    Ok(line.trim().to_owned())
}

pub fn require_terminal() -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "interactive mode requires a terminal"
    );
    Ok(())
}

pub fn with_terminal<T>(
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

fn identity_backends() -> Vec<Box<dyn IdentityBackend>> {
    vec![Box::new(backends::yubikey::YubiKeyBackend)]
}

fn choose_identity_tui(
    identities: Vec<DiscoveredIdentity>,
    purpose: &str,
) -> Result<DiscoveredIdentity> {
    let mut selected = 0usize;
    let selected = with_terminal(|terminal| loop {
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(4), Constraint::Length(3)])
                .split(frame.area());
            let items = identities
                .iter()
                .map(|identity| {
                    ListItem::new(format!("  {}  {}", identity.display_name, identity.detail))
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
                selected = (selected + 1).min(identities.len() - 1)
            }
            InputKey::Up | InputKey::Char('k') => selected = selected.saturating_sub(1),
            InputKey::Enter => break Ok(selected),
            InputKey::Esc | InputKey::Char('q') => bail!("identity selection cancelled"),
            _ => {}
        }
    })?;
    Ok(identities[selected].clone())
}
