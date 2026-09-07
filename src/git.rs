use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use anyhow::{ensure, Context, Result};

use crate::event::{EventLog, Hash, MAX_LOG_SIZE};

const LOG_PATH: &str = "vault.log";
const LOCAL_CHECKPOINT_MAGIC: &[u8; 8] = b"GVLCP001";

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
        let recovery_ack = recovery_ack_ref(vault);
        let mut references = self
            .list_refs("refs/vaults/")?
            .into_iter()
            .filter(|reference| reference == &primary)
            .chain(
                self.list_refs("refs/vault-local/")?
                    .into_iter()
                    .filter(|reference| reference == &local),
            )
            .collect::<Vec<_>>();
        references.extend(
            self.list_refs("refs/vault-recovery-ack/")?
                .into_iter()
                .filter(|reference| reference == &recovery_ack),
        );
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

    pub fn write_merged_vault_log(
        &self,
        vault: &str,
        expected_local_commit: Option<&str>,
        other_parent: &str,
        log: &EventLog,
        message: &str,
    ) -> Result<String> {
        validate_vault_name(vault)?;
        validate_oid(other_parent)?;
        if let Some(local) = expected_local_commit {
            validate_oid(local)?;
        }
        let encoded = log.encode()?;
        ensure!(
            encoded.len() <= MAX_LOG_SIZE,
            "vault event collection exceeds the size limit"
        );
        let blob = self.hash_object(&encoded)?;
        let tree_input = format!("100644 blob {blob}\t{LOG_PATH}\n");
        let tree = self.git_text_with_input(["mktree"], tree_input.as_bytes())?;
        let mut arguments = vec!["commit-tree".to_owned(), tree.trim().to_owned()];
        if let Some(local) = expected_local_commit {
            arguments.push("-p".into());
            arguments.push(local.into());
        }
        if expected_local_commit != Some(other_parent) {
            arguments.push("-p".into());
            arguments.push(other_parent.into());
        }
        arguments.push("-m".into());
        arguments.push(message.into());
        let commit = self.git_text(arguments)?.trim().to_owned();
        validate_oid(&commit)?;

        let reference = vault_ref(vault);
        let old = expected_local_commit
            .map(str::to_owned)
            .unwrap_or_else(|| "0".repeat(commit.len()));
        let output = self.git_output(["update-ref", &reference, &commit, &old], None)?;
        ensure!(
            output.status.success(),
            "vault changed concurrently; fetch and merge again"
        );
        Ok(commit)
    }

    pub fn read_local_checkpoint(&self, vault: &str) -> Result<Option<Vec<Hash>>> {
        validate_vault_name(vault)?;
        let reference = local_ref(vault);
        let Some(oid) = self.resolve_ref(&reference, "blob")? else {
            return Ok(None);
        };
        let bytes = self.git_bytes(["cat-file", "blob", &oid])?;
        ensure!(
            bytes.len() >= 12 && &bytes[..8] == LOCAL_CHECKPOINT_MAGIC,
            "local freshness checkpoint is malformed"
        );
        let count = u32::from_be_bytes(bytes[8..12].try_into().expect("length checked")) as usize;
        ensure!(
            count <= MAX_LOG_SIZE / 32 && bytes.len() == 12 + count * 32,
            "local freshness checkpoint is malformed"
        );
        let mut hashes = Vec::with_capacity(count);
        for chunk in bytes[12..].chunks_exact(32) {
            hashes.push(chunk.try_into().expect("length checked"));
        }
        ensure!(
            hashes.windows(2).all(|pair| pair[0] < pair[1]),
            "local freshness checkpoint is not canonical"
        );
        Ok(Some(hashes))
    }

    pub fn write_local_checkpoint(&self, vault: &str, hashes: &[Hash]) -> Result<()> {
        validate_vault_name(vault)?;
        let mut hashes = hashes.to_vec();
        hashes.sort();
        hashes.dedup();
        ensure!(
            hashes.len() <= MAX_LOG_SIZE / 32,
            "local freshness checkpoint is too large"
        );
        let mut encoded = Vec::with_capacity(12 + hashes.len() * 32);
        encoded.extend_from_slice(LOCAL_CHECKPOINT_MAGIC);
        encoded.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
        for hash in hashes {
            encoded.extend_from_slice(&hash);
        }
        let reference = local_ref(vault);
        let old = self.resolve_ref(&reference, "blob")?;
        let blob = self.hash_object(&encoded)?;
        let old = old.unwrap_or_else(|| "0".repeat(blob.len()));
        let output = self.git_output(["update-ref", &reference, &blob, &old], None)?;
        ensure!(
            output.status.success(),
            "local freshness checkpoint changed concurrently"
        );
        Ok(())
    }

    pub fn has_unrecoverable_ack(&self, vault: &str, vault_id: &Hash) -> Result<bool> {
        validate_vault_name(vault)?;
        let reference = recovery_ack_ref(vault);
        let Some(oid) = self.resolve_ref(&reference, "blob")? else {
            return Ok(false);
        };
        Ok(self.git_bytes(["cat-file", "blob", &oid])? == vault_id)
    }

    pub fn write_unrecoverable_ack(&self, vault: &str, vault_id: &Hash) -> Result<()> {
        validate_vault_name(vault)?;
        let reference = recovery_ack_ref(vault);
        let old = self.resolve_ref(&reference, "blob")?;
        let blob = self.hash_object(vault_id)?;
        let old = old.unwrap_or_else(|| "0".repeat(blob.len()));
        let output = self.git_output(["update-ref", &reference, &blob, &old], None)?;
        ensure!(
            output.status.success(),
            "unrecoverable acknowledgement changed concurrently"
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
        let log = EventLog::decode(&bytes).context("cannot parse vault event collection")?;
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

fn recovery_ack_ref(vault: &str) -> String {
    format!("refs/vault-recovery-ack/{vault}")
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

        repository
            .write_local_checkpoint("prod", &[[7; 32]])
            .unwrap();
        assert_eq!(
            repository.read_local_checkpoint("prod").unwrap(),
            Some(vec![[7; 32]])
        );
        assert!(!repository.has_unrecoverable_ack("prod", &[8; 32]).unwrap());
        repository
            .write_unrecoverable_ack("prod", &[8; 32])
            .unwrap();
        assert!(repository.has_unrecoverable_ack("prod", &[8; 32]).unwrap());

        let archive = repository
            .append_vault_log("archive", None, &log, "create another vault")
            .unwrap();
        let merged = repository
            .write_merged_vault_log(
                "prod",
                Some(&first),
                &archive,
                &log,
                "merge event collections",
            )
            .unwrap();
        for parent in [&first, &archive] {
            let output = repository
                .git_output(["merge-base", "--is-ancestor", parent, &merged], None)
                .unwrap();
            assert!(output.status.success());
        }
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
