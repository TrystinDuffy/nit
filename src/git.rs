use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use anyhow::{ensure, Context, Result};

use crate::event::{EventLog, Hash, MAX_LOG_SIZE};

const LOG_PATH: &str = "vault.log";

#[derive(Clone, Debug)]
pub struct StoredLog {
    pub commit_oid: String,
    pub log: EventLog,
}

#[derive(Clone, Debug)]
pub struct GitRepository {
    workdir: PathBuf,
}

impl GitRepository {
    pub fn discover(path: impl AsRef<Path>) -> Result<Self> {
        let output = Command::new("git")
            .arg("-C")
            .arg(path.as_ref())
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .context("cannot execute Git")?;
        ensure!(
            output.status.success(),
            "git-vault must run inside a Git working tree"
        );
        let workdir = String::from_utf8(output.stdout)
            .context("Git returned a non-UTF-8 working tree path")?;
        Ok(Self {
            workdir: PathBuf::from(workdir.trim()),
        })
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub fn list_vaults(&self) -> Result<Vec<String>> {
        let prefix = "refs/vaults/";
        let mut vaults = self
            .list_refs(prefix)?
            .into_iter()
            .filter_map(|reference| reference.strip_prefix(prefix).map(str::to_owned))
            .filter(|name| !name.contains('/') && validate_vault_name(name).is_ok())
            .collect::<Vec<_>>();
        vaults.sort();
        vaults.dedup();
        Ok(vaults)
    }

    /// Deletes all local refs owned by one vault. Remote repository refs and
    /// unreachable Git objects are intentionally not deleted.
    pub fn delete_vault(&self, vault: &str) -> Result<usize> {
        validate_vault_name(vault)?;
        let primary = vault_ref(vault);
        let local = local_ref(vault);
        let onboarding_prefix = format!("refs/vault-onboarding/{vault}/");
        let mut references = self
            .list_refs("refs/vaults/")?
            .into_iter()
            .filter(|reference| reference == &primary)
            .chain(
                self.list_refs("refs/vault-local/")?
                    .into_iter()
                    .filter(|reference| reference == &local),
            )
            .chain(self.list_refs(&onboarding_prefix)?)
            .collect::<Vec<_>>();
        references.extend(
            self.list_refs("refs/vault-remotes/")?
                .into_iter()
                .filter(|reference| reference.rsplit('/').next() == Some(vault)),
        );
        references.sort();
        references.dedup();
        if references.is_empty() {
            return Ok(0);
        }
        let mut transaction = String::from("start\n");
        for reference in &references {
            transaction.push_str("delete ");
            transaction.push_str(reference);
            transaction.push('\n');
        }
        transaction.push_str("prepare\ncommit\n");
        let output = self.git_output(["update-ref", "--stdin"], Some(transaction.as_bytes()))?;
        ensure!(
            output.status.success(),
            "cannot delete vault refs: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(references.len())
    }

    pub fn read_vault(&self, vault: &str) -> Result<Option<StoredLog>> {
        validate_vault_name(vault)?;
        self.read_ref_log(&vault_ref(vault))
    }

    pub fn read_remote_vault(&self, remote: &str, vault: &str) -> Result<Option<StoredLog>> {
        validate_remote_name(remote)?;
        validate_vault_name(vault)?;
        self.read_ref_log(&remote_vault_ref(remote, vault))
    }

    pub fn append_vault_log(
        &self,
        vault: &str,
        expected_commit: Option<&str>,
        log: &EventLog,
        message: &str,
    ) -> Result<String> {
        validate_vault_name(vault)?;
        let encoded = log.encode()?;
        ensure!(
            encoded.len() <= MAX_LOG_SIZE,
            "vault log exceeds the size limit"
        );
        let blob = self.hash_object(&encoded)?;
        let tree_input = format!("100644 blob {blob}\t{LOG_PATH}\n");
        let tree = self.git_text_with_input(["mktree"], tree_input.as_bytes())?;
        let mut arguments = vec!["commit-tree", tree.trim()];
        if let Some(parent) = expected_commit {
            validate_oid(parent)?;
            arguments.extend(["-p", parent]);
        }
        arguments.extend(["-m", message]);
        let commit = self.git_text(arguments)?;
        let commit = commit.trim().to_owned();
        validate_oid(&commit)?;

        let reference = vault_ref(vault);
        let old = match expected_commit {
            Some(oid) => oid.to_owned(),
            None => "0".repeat(commit.len()),
        };
        let output = self.git_output(["update-ref", &reference, &commit, &old], None)?;
        ensure!(
            output.status.success(),
            "vault changed concurrently; reload it before appending another event"
        );
        Ok(commit)
    }

    pub fn read_local_checkpoint(&self, vault: &str) -> Result<Option<Hash>> {
        validate_vault_name(vault)?;
        let reference = local_ref(vault);
        let Some(oid) = self.resolve_ref(&reference, "blob")? else {
            return Ok(None);
        };
        let bytes = self.git_bytes(["cat-file", "blob", &oid])?;
        ensure!(bytes.len() == 32, "local freshness checkpoint is malformed");
        Ok(Some(bytes.try_into().expect("length checked")))
    }

    pub fn write_local_checkpoint(&self, vault: &str, hash: &Hash) -> Result<()> {
        validate_vault_name(vault)?;
        let reference = local_ref(vault);
        let old = self.resolve_ref(&reference, "blob")?;
        let blob = self.hash_object(hash)?;
        let old = old.unwrap_or_else(|| "0".repeat(blob.len()));
        let output = self.git_output(["update-ref", &reference, &blob, &old], None)?;
        ensure!(
            output.status.success(),
            "local freshness checkpoint changed concurrently"
        );
        Ok(())
    }

    pub fn read_onboarding_state(&self, vault: &str, event_hash: &Hash) -> Result<Vec<u8>> {
        validate_vault_name(vault)?;
        let reference = onboarding_ref(vault, event_hash);
        let oid = self
            .resolve_ref(&reference, "blob")?
            .context("local onboarding state is absent on this machine")?;
        self.git_bytes(["cat-file", "blob", &oid])
    }

    pub fn write_onboarding_state(
        &self,
        vault: &str,
        event_hash: &Hash,
        bytes: &[u8],
    ) -> Result<()> {
        validate_vault_name(vault)?;
        ensure!(
            bytes.len() <= 256 * 1024,
            "local onboarding state is too large"
        );
        let reference = onboarding_ref(vault, event_hash);
        let old = self.resolve_ref(&reference, "blob")?;
        let blob = self.hash_object(bytes)?;
        let old = old.unwrap_or_else(|| "0".repeat(blob.len()));
        let output = self.git_output(["update-ref", &reference, &blob, &old], None)?;
        ensure!(
            output.status.success(),
            "local onboarding state changed concurrently"
        );
        Ok(())
    }

    pub fn delete_onboarding_state(&self, vault: &str, event_hash: &Hash) -> Result<()> {
        validate_vault_name(vault)?;
        let reference = onboarding_ref(vault, event_hash);
        let Some(old) = self.resolve_ref(&reference, "blob")? else {
            return Ok(());
        };
        let output = self.git_output(["update-ref", "-d", &reference, &old], None)?;
        ensure!(
            output.status.success(),
            "local onboarding state changed concurrently"
        );
        Ok(())
    }

    pub fn advance_vault_ref(
        &self,
        vault: &str,
        expected_commit: Option<&str>,
        new_commit: &str,
    ) -> Result<()> {
        validate_vault_name(vault)?;
        validate_oid(new_commit)?;
        let old = expected_commit
            .map(str::to_owned)
            .unwrap_or_else(|| "0".repeat(new_commit.len()));
        let reference = vault_ref(vault);
        let output = self.git_output(["update-ref", &reference, new_commit, &old], None)?;
        ensure!(
            output.status.success(),
            "vault ref changed concurrently; fetch and verify again"
        );
        Ok(())
    }

    pub fn fetch_vault(&self, remote: &str, vault: &str) -> Result<()> {
        validate_remote_name(remote)?;
        validate_vault_name(vault)?;
        let source = vault_ref(vault);
        let destination = remote_vault_ref(remote, vault);
        let refspec = format!("+{source}:{destination}");
        let output = self.git_output(["fetch", "--no-tags", remote, &refspec], None)?;
        ensure!(
            output.status.success(),
            "cannot fetch vault {vault:?} from remote {remote:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    pub fn push_vault(&self, remote: &str, vault: &str) -> Result<()> {
        validate_remote_name(remote)?;
        validate_vault_name(vault)?;
        let reference = vault_ref(vault);
        let refspec = format!("{reference}:{reference}");
        let output = self.git_output(["push", remote, &refspec], None)?;
        ensure!(
            output.status.success(),
            "cannot push vault {vault:?} to remote {remote:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    fn list_refs(&self, prefix: &str) -> Result<Vec<String>> {
        let output = self.git_text(["for-each-ref", "--format=%(refname)", prefix])?;
        Ok(output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect())
    }

    fn read_ref_log(&self, reference: &str) -> Result<Option<StoredLog>> {
        let Some(commit_oid) = self.resolve_ref(reference, "commit")? else {
            return Ok(None);
        };
        let object = format!("{commit_oid}:{LOG_PATH}");
        let bytes = self.git_bytes(["show", &object])?;
        let log = EventLog::decode(&bytes).context("cannot parse append-only vault log")?;
        Ok(Some(StoredLog { commit_oid, log }))
    }

    fn resolve_ref(&self, reference: &str, kind: &str) -> Result<Option<String>> {
        let expression = format!("{reference}^{{{kind}}}");
        let output = self.git_output(["rev-parse", "--verify", "--quiet", &expression], None)?;
        if !output.status.success() {
            return Ok(None);
        }
        let oid = String::from_utf8(output.stdout).context("Git returned a non-UTF-8 object ID")?;
        let oid = oid.trim().to_owned();
        validate_oid(&oid)?;
        Ok(Some(oid))
    }

    fn hash_object(&self, bytes: &[u8]) -> Result<String> {
        let oid = self.git_text_with_input(["hash-object", "-w", "--stdin"], bytes)?;
        let oid = oid.trim().to_owned();
        validate_oid(&oid)?;
        Ok(oid)
    }

    fn git_text<I, S>(&self, arguments: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.git_output(arguments, None)?;
        ensure!(
            output.status.success(),
            "Git plumbing command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        String::from_utf8(output.stdout).context("Git returned non-UTF-8 output")
    }

    fn git_text_with_input<I, S>(&self, arguments: I, input: &[u8]) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.git_output(arguments, Some(input))?;
        ensure!(
            output.status.success(),
            "Git plumbing command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        String::from_utf8(output.stdout).context("Git returned non-UTF-8 output")
    }

    fn git_bytes<I, S>(&self, arguments: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.git_output(arguments, None)?;
        ensure!(
            output.status.success(),
            "Git plumbing command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    fn git_output<I, S>(&self, arguments: I, input: Option<&[u8]>) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new("git");
        command.arg("-C").arg(&self.workdir).args(arguments);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command.env("GIT_AUTHOR_NAME", "git-vault");
        command.env("GIT_AUTHOR_EMAIL", "git-vault@localhost");
        command.env("GIT_COMMITTER_NAME", "git-vault");
        command.env("GIT_COMMITTER_EMAIL", "git-vault@localhost");
        let mut child = command.spawn().context("cannot execute Git")?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .context("cannot open Git stdin")?
                .write_all(input)
                .context("cannot write Git plumbing input")?;
        }
        child.wait_with_output().context("cannot wait for Git")
    }
}

pub fn validate_vault_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 64,
        "vault name must contain 1–64 characters"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "vault name may contain only ASCII letters, digits, '.', '_', and '-'"
    );
    ensure!(
        !name.starts_with('.')
            && !name.ends_with('.')
            && !name.contains("..")
            && !name.ends_with(".lock"),
        "vault name is not safe for a Git ref"
    );
    Ok(())
}

fn validate_remote_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') }),
        "remote name is not safe for a Git ref"
    );
    Ok(())
}

fn validate_oid(oid: &str) -> Result<()> {
    ensure!(
        matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Git returned an invalid object ID"
    );
    Ok(())
}

fn vault_ref(vault: &str) -> String {
    format!("refs/vaults/{vault}")
}

fn remote_vault_ref(remote: &str, vault: &str) -> String {
    format!("refs/vault-remotes/{remote}/{vault}")
}

fn local_ref(vault: &str) -> String {
    format!("refs/vault-local/{vault}")
}

fn onboarding_ref(vault: &str, event_hash: &Hash) -> String {
    format!("refs/vault-onboarding/{vault}/{}", hex::encode(event_hash))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn custom_ref_round_trip_and_cas() {
        let directory = TempDir::new().unwrap();
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(directory.path())
            .status()
            .unwrap();
        fs::write(directory.path().join("README"), "test").unwrap();
        let repository = GitRepository::discover(directory.path()).unwrap();
        let log = EventLog::default();
        let first = repository
            .append_vault_log("prod", None, &log, "create vault")
            .unwrap();
        let loaded = repository.read_vault("prod").unwrap().unwrap();
        assert_eq!(loaded.commit_oid, first);
        assert!(loaded.log.events.is_empty());
        assert!(repository
            .append_vault_log("prod", None, &log, "stale create")
            .is_err());

        repository.write_local_checkpoint("prod", &[7; 32]).unwrap();
        assert_eq!(
            repository.read_local_checkpoint("prod").unwrap(),
            Some([7; 32])
        );

        repository
            .write_onboarding_state("prod", &[8; 32], b"pake-state")
            .unwrap();
        assert_eq!(
            repository.read_onboarding_state("prod", &[8; 32]).unwrap(),
            b"pake-state"
        );
        repository
            .delete_onboarding_state("prod", &[8; 32])
            .unwrap();
        assert!(repository.read_onboarding_state("prod", &[8; 32]).is_err());

        repository
            .append_vault_log("archive", None, &log, "create another vault")
            .unwrap();
        repository
            .write_onboarding_state("prod", &[9; 32], b"pending")
            .unwrap();
        repository
            .git_output(
                [
                    "update-ref",
                    "refs/vault-remotes/origin/prod",
                    first.as_str(),
                ],
                None,
            )
            .unwrap();
        assert_eq!(
            repository.list_vaults().unwrap(),
            vec!["archive".to_owned(), "prod".to_owned()]
        );
        assert_eq!(repository.delete_vault("prod").unwrap(), 4);
        assert!(repository.read_vault("prod").unwrap().is_none());
        assert!(repository.read_local_checkpoint("prod").unwrap().is_none());
        assert_eq!(repository.list_vaults().unwrap(), vec!["archive"]);
    }

    #[test]
    fn rejects_unsafe_ref_names() {
        for name in ["", ".prod", "a/b", "a..b", "prod.lock", "white space"] {
            assert!(validate_vault_name(name).is_err(), "accepted {name:?}");
        }
    }
}
