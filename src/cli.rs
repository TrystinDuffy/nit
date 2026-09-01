use clap::{Parser, Subcommand, ValueEnum};

use crate::event::{Role, ValueType};

#[derive(Debug, Parser)]
#[command(
    name = "git-vault",
    bin_name = "git vault",
    version,
    about = "Append-only, Git-native, hardware-backed secret vault"
)]
pub struct Cli {
    /// Vault name under refs/vaults/<name>; omit to open the repository vault manager
    pub vault: Option<String>,

    /// Select a YubiKey serial number or "touchid"
    #[arg(long, value_name = "IDENTITY")]
    pub identity: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List secret keys
    List,
    /// Print one secret value
    Get { key: String },
    /// Append a typed Put event
    Set {
        key: String,
        #[arg(long, value_enum, default_value_t = CliValueType::Text)]
        r#type: CliValueType,
        /// Read the value from stdin instead of a secure terminal prompt
        #[arg(long)]
        stdin: bool,
    },
    /// Append a Delete event
    Delete { key: String },
    /// List trusted members
    Members,
    /// Add a physically present identity and rotate the membership epoch
    AddMember {
        #[arg(long)]
        name: String,
        /// Select the new identity; --identity continues to select the current owner
        #[arg(long, value_name = "IDENTITY")]
        new_identity: Option<String>,
        /// Member can read/write secrets; owner can also manage access
        #[arg(long, value_enum, default_value_t = CliRole::Member)]
        capability: CliRole,
    },
    /// Remove a trusted member and rotate the membership epoch
    RemoveMember { member: String },
    /// Change a trusted member's capability and rotate the membership epoch
    SetRole {
        member: String,
        #[arg(value_enum)]
        role: CliRole,
    },
    /// Irreversibly replace the selected YubiKey identity with keys requiring no PIN or touch
    DestroyIdentity,
    /// Verify and summarize the trusted projection without unlocking values
    Verify,
    /// Fetch into refs/vault-remotes/<remote>/<vault>, verify, then CAS-advance
    Fetch {
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Push refs/vaults/<vault> without forcing
    Push {
        #[arg(default_value = "origin")]
        remote: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliRole {
    #[value(alias = "reader")]
    Member,
    Owner,
}

impl From<CliRole> for Role {
    fn from(value: CliRole) -> Self {
        match value {
            CliRole::Member => Self::Member,
            CliRole::Owner => Self::Owner,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CliValueType {
    Text,
    Number,
    Boolean,
    Bytes,
}

impl From<CliValueType> for ValueType {
    fn from(value: CliValueType) -> Self {
        match value {
            CliValueType::Text => Self::Text,
            CliValueType::Number => Self::Number,
            CliValueType::Boolean => Self::Boolean,
            CliValueType::Bytes => Self::Bytes,
        }
    }
}
