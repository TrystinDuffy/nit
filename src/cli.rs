use std::ffi::OsString;

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
    /// Run a child process with explicitly selected secrets in its environment
    Exec {
        /// Map ENV_NAME=VAULT_KEY, or use one name for both
        #[arg(long = "env", value_name = "ENV_NAME[=VAULT_KEY]", required = true)]
        environment: Vec<String>,
        /// Program and arguments; must follow `--`
        #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        child: Vec<OsString>,
    },
    /// Explicitly accept that loss of the sole owner identity permanently loses the vault
    AcknowledgeUnrecoverable,
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
    /// Safely commission a replacement owner, prove recovery, then remove this identity
    RotateIdentity {
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "IDENTITY")]
        new_identity: Option<String>,
    },
    /// Remove a trusted member and rotate the membership epoch
    RemoveMember { member: String },
    /// Change a trusted member's capability and rotate the membership epoch
    SetRole {
        member: String,
        #[arg(value_enum)]
        role: CliRole,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_accepts_same_name_renamed_and_literal_child_arguments() {
        let cli = Cli::try_parse_from([
            "git-vault",
            "staging",
            "exec",
            "--env",
            "TOKEN",
            "--env",
            "API_TOKEN=TOKEN",
            "--",
            "program",
            "--literal=$TOKEN",
            "*.txt",
        ])
        .unwrap();
        let Some(Command::Exec { environment, child }) = cli.command else {
            panic!("expected exec command");
        };
        assert_eq!(environment, ["TOKEN", "API_TOKEN=TOKEN"]);
        assert_eq!(
            child,
            ["program", "--literal=$TOKEN", "*.txt"].map(OsString::from)
        );
    }

    #[test]
    fn exec_requires_an_environment_mapping_and_child_command() {
        assert!(Cli::try_parse_from(["git-vault", "staging", "exec", "--", "program"]).is_err());
        assert!(Cli::try_parse_from(["git-vault", "staging", "exec", "--env", "TOKEN"]).is_err());
    }

    #[test]
    fn exec_requires_the_child_command_separator() {
        assert!(
            Cli::try_parse_from(["git-vault", "staging", "exec", "--env", "TOKEN", "program"])
                .is_err()
        );
    }

    #[test]
    fn existing_commands_and_interactive_mode_still_parse() {
        for arguments in [
            vec!["git-vault", "staging"],
            vec!["git-vault", "staging", "list"],
            vec!["git-vault", "staging", "get", "TOKEN"],
            vec!["git-vault", "staging", "set", "TOKEN", "--stdin"],
            vec!["git-vault", "staging", "delete", "TOKEN"],
            vec!["git-vault", "staging", "members"],
            vec!["git-vault", "staging", "verify"],
            vec!["git-vault", "staging", "fetch", "origin"],
            vec!["git-vault", "staging", "push", "origin"],
        ] {
            assert!(
                Cli::try_parse_from(arguments.clone()).is_ok(),
                "failed to parse {arguments:?}"
            );
        }
    }
}
