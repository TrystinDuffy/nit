mod app;
mod crypto;
mod keys;
mod yubikey;

use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use app::{App, Effect, Mode};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crypto::{Envelope, Vault};
use keys::{parse_keys, InputKey};
use ratatui::{backend::CrosstermBackend, Terminal};
use tempfile::NamedTempFile;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(
    name = "nit",
    version,
    about = "A tiny YubiKey-backed encrypted secret vault"
)]
struct Cli {
    /// Encrypted secret vault to open (created if absent)
    file: PathBuf,

    /// Feed synthetic keys to the same interface state machine
    #[arg(short = 'k', long = "keys", value_name = "KEYS")]
    keys: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nit: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let (vault, recipient) = if cli.file.exists() {
        open_vault(&cli.file)?
    } else {
        create_vault(&cli.file)?
    };

    let mut app = App::new(vault);
    let mut outputs = Vec::new();

    if let Some(sequence) = cli.keys {
        let needs_stdin = sequence.to_ascii_lowercase().contains("<stdin>");
        let mut stdin_value = String::new();
        if needs_stdin {
            io::stdin()
                .read_to_string(&mut stdin_value)
                .context("failed to read <stdin> value")?;
        }
        let inputs = parse_keys(&sequence, &stdin_value)?;
        for input in inputs {
            if handle_input(&mut app, input, &cli.file, &recipient, &mut outputs)? {
                break;
            }
        }
    } else {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("interactive mode needs a terminal; use -k to automate the interface");
        }
        run_tui(&mut app, &cli.file, &recipient, &mut outputs)?;
    }

    for mut value in outputs {
        println!("{value}");
        value.zeroize();
    }
    Ok(())
}

fn open_vault(path: &Path) -> Result<(Vault, crypto::Recipient)> {
    let metadata =
        fs::metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    if metadata.len() > crypto::MAX_FILE_SIZE {
        bail!("{} is larger than the 64 MiB vault limit", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let envelope = Envelope::decode(&bytes)?;
    let recipient = envelope.recipient();

    eprintln!(
        "Unlocking {} with YubiKey {} (slot {:02x})…",
        path.display(),
        recipient.serial,
        recipient.slot
    );
    let mut key = yubikey::YubiKey::open(Some(recipient.serial))?;
    let pin = rpassword::prompt_password("PIV PIN: ").context("failed to read PIV PIN")?;
    if pin.is_empty() {
        bail!("an empty PIV PIN was not sent to the YubiKey");
    }
    key.verify_pin(&pin)?;
    eprintln!("Touch the YubiKey to unlock the vault…");
    let vault = envelope.open(|ephemeral| key.agree(recipient.slot, ephemeral))?;
    Ok((vault, recipient))
}

fn create_vault(path: &Path) -> Result<(Vault, crypto::Recipient)> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.exists() {
            bail!("parent directory {} does not exist", parent.display());
        }
    }
    eprintln!("Creating {} with a YubiKey X25519 key…", path.display());
    let mut key = yubikey::YubiKey::open(None)?;
    let recipient = key.ensure_x25519_key(yubikey::DEFAULT_SLOT)?;
    let vault = Vault::default();
    save_vault(path, &vault, &recipient)?;
    eprintln!(
        "Created vault for YubiKey {} in slot {:02x}.",
        recipient.serial, recipient.slot
    );
    Ok((vault, recipient))
}

fn save_vault(path: &Path, vault: &Vault, recipient: &crypto::Recipient) -> Result<()> {
    let encoded = Envelope::seal(vault, recipient)?.encode()?;
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

fn handle_input(
    app: &mut App,
    input: InputKey,
    path: &Path,
    recipient: &crypto::Recipient,
    outputs: &mut Vec<String>,
) -> Result<bool> {
    match app.input(input) {
        Effect::None => Ok(false),
        Effect::Changed => {
            save_vault(path, app.vault(), recipient)?;
            Ok(false)
        }
        Effect::Output(value) => {
            outputs.push(value);
            Ok(false)
        }
        Effect::Quit => Ok(true),
    }
}

fn run_tui(
    app: &mut App,
    path: &Path,
    recipient: &crypto::Recipient,
    outputs: &mut Vec<String>,
) -> Result<()> {
    enable_raw_mode().context("cannot enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("cannot enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("cannot initialize terminal")?;

    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| app::draw(frame, app, path))?;
            if !event::poll(Duration::from_millis(250))? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let input = match key.code {
                KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    InputKey::Esc
                }
                KeyCode::Char(character) => InputKey::Char(character),
                KeyCode::Enter => InputKey::Enter,
                KeyCode::Esc => InputKey::Esc,
                KeyCode::Up => InputKey::Up,
                KeyCode::Down => InputKey::Down,
                KeyCode::Backspace => InputKey::Backspace,
                KeyCode::Tab => InputKey::Tab,
                _ => continue,
            };
            if handle_input(app, input, path, recipient, outputs)? {
                break;
            }
        }
        Ok(())
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    if !matches!(app.mode(), Mode::List) {
        app.cancel();
    }
    result
}
