# v1 threat model

This document defines the security boundary for the v1 design. It is a design target, not a claim that this early prototype has completed an independent audit or the physical testing listed elsewhere.

## Assets and principals

The protected assets are secret values, current epoch keys, identity private keys, and the integrity of the derived membership and value state.

A **member** is authorized to read and mutate every secret in a vault. An **owner** has the same access and may also change membership. Git hosts, repository administrators, network peers, and processes that merely possess a repository are untrusted.

The trusted computing base for an operation includes the `git-vault` binary and its cryptographic dependencies, the endpoint kernel and relevant device services, the terminal/UI used for authorization, and the selected identity device. Hardware-backed identity keys do not make a compromised endpoint trustworthy: plaintext and epoch keys necessarily reach the endpoint while a vault is unlocked.

## Security goals

Subject to the assumptions and profile limits below, v1 aims to provide:

- **Confidentiality at rest and in transport.** Possession of Git objects, backups, or network traffic does not reveal secret names or values. Public metadata still reveals the items listed below.
- **Authenticity and authorization.** Forging a trusted mutation requires a current member signing key. Forging a membership transition requires a current owner signing key.
- **Deterministic replay.** Clients given the same event set derive the same membership chain, mutation order, and displayed values.
- **Fail-closed membership forks.** Competing authorized membership transitions are not silently resolved.
- **Safe concurrent data writes.** Authorized concurrent mutations can be unioned without becoming a membership fork; same-key concurrency is surfaced and resolved by the specified deterministic ordering.
- **Removal for future epochs.** A removed member receives no newly generated epoch key and cannot authorize later events. Data and epoch keys obtained before removal cannot be revoked.
- **Tamper and omission detection where anchored.** Signatures reject modification and fabrication. A retained local accepted-event checkpoint detects omission of previously accepted events in that repository. A valid external identity checkpoint additionally detects membership rollback or replacement relative to that identity's last accepted epoch.
- **Non-exportability of hardware identity keys.** With a supported YubiKey, X25519 and Ed25519 private identity keys are generated and used in PIV slots rather than exported by the application. This does not prevent an authorized or compromised host from asking a connected token to operate.

## Adversaries covered

The design treats the following as hostile:

- a Git server, mirror, backup operator, repository administrator, or network attacker that reads, withholds, reorders, duplicates, truncates, replaces, or appends Git objects and refs;
- an outsider that obtains any number of repository copies but no authorized identity or plaintext from an unlocked endpoint;
- a former member attempting to append mutations after a membership epoch that removed them;
- malformed or oversized event input within the documented parser and collection limits;
- accidental concurrent writes by authorized members;
- loss or failure of one identity when a distinct, tested owner recovery identity remains available.

Cryptography cannot guarantee availability. Hostile storage may refuse all reads/writes, discard the only copy, retain stale refs, or exhaust the bounded log with garbage. Such behavior should fail visibly, but v1 does not make the service available.

## Explicitly unprotected threats and non-goals

The following are outside v1's confidentiality guarantee:

- **A compromised endpoint while the vault is unlocked.** It can read plaintext, epoch keys, clipboard/terminal output, and application memory. It may alter user input or invoke a connected identity subject to that identity's PIN/touch policy. Hardware keys limit key extraction; they do not protect plaintext from the host performing decryption.
- **A malicious authorized member.** Any member may copy and disclose every secret and may retain epoch keys or plaintext forever. A malicious member may make destructive or misleading value mutations. A malicious owner may also add identities, remove members, or deliberately create a membership fork. Auditability and deterministic replay do not restore confidentiality once an authorized principal discloses data.
- **A caller or child using `exec`.** A caller authorized to execute an arbitrary child process with a secret in its environment should be considered capable of reading that secret. The child and sufficiently privileged OS observers may copy, print, retain, inspect, or propagate its environment. Nit avoids its own routine printing and env-file handling, but `exec` is an ergonomic delivery mechanism rather than a security boundary or sandbox. Nit cannot guarantee zeroization of environment copies made by the operating system or receiving process.

V1 also does not promise:

- availability against a Git host, repository writer, network adversary, or destructive authorized member;
- revocation of historical plaintext, old epoch keys, screenshots, exports, backups, or previously fetched ciphertext;
- recovery when all owner/recovery identities and all unlocked copies are lost; the local unrecoverable acknowledgement changes no cryptographic property;
- rollback detection on a brand-new clone with no trusted external checkpoint, or against an attacker that can roll back both the repository and every relevant local/software checkpoint;
- protection from endpoint compromise before unlock, malicious binaries or dependencies, firmware/hardware compromise, side channels, coercion, shoulder surfing, weak PINs, or denial through PIN retry exhaustion;
- hiding vault existence, event count and sizes, timing, membership epochs, public identity keys, roles, or Git transport metadata;
- anonymous membership, per-secret ACLs, multi-party approval, owner quorum, forward secrecy within an epoch, post-compromise security, or remote deletion;
- guaranteed forensic erasure from Git object databases, remotes, reflogs, filesystems, swap, crash dumps, or backups;
- automatic identity authenticity for imported public material. Directly connected commissioning proves possession, not the person's real-world identity. Any future remote identity-card path must require an out-of-band fingerprint comparison;
- safe operation with factory-default management credentials as a strong independent rollback anchor;
- production-grade power-loss atomicity, capacity, or endurance for the current YubiKey checkpoint object until the documented physical tests are complete.

## Hardware-use profiles

Profiles change resistance to token theft and unattended host abuse; they do not change event authorization or protect an unlocked compromised endpoint. PIN and touch policy is immutable for a generated PIV key, so moving profiles requires commissioning a distinct identity rather than overwriting an in-use one.

### Balanced

Intended for interactive daily use and implemented by normal provisioning:

```text
X25519 decrypt/agreement   PIN once, touch always
Ed25519 mutation signing  PIN once, touch cached
```

Assumptions: the endpoint is maintained and trusted while unlocked; the token is removed or the session is locked when unattended; the user verifies unexpected touch requests; the PIV management key is changed from its factory default and stored separately when hardware rollback claims matter.

This profile resists use of a stolen, locked token without its PIN and requires physical presence for each decrypt/agreement. Cached signing touch reduces repeated prompts, so malware running during that cache window may sign mutations. It does not provide deliberate per-mutation approval.

### High-security

Intended for sensitive, infrequent access. Use dedicated owner tokens, keep at least one tested recovery owner offline, use non-default strong PIN and management credentials, require touch for every private-key operation, and perform operations on a hardened or offline endpoint before transporting only encrypted Git objects.

The prototype does not yet provision a separate touch-protected owner-control key or expose a complete high-security policy selector. Until that exists, the normal balanced signing key and its cached-touch behavior are not equivalent to deliberate approval of each mutation or membership operation.

This profile improves resistance to opportunistic remote use of an attached token and compromise of ordinary online hosts. It still does not protect secrets once the hardened endpoint used for an unlock is compromised, nor does one user's touch prove that the UI displayed the bytes actually signed.

### Unattended

Intended only for automation where no person can supply PIN/touch. It requires a separately pre-provisioned identity whose policies permit unattended use; the normal provisioning and safe-rotation workflow do not weaken an existing identity in place.

Assumptions: the automation host, process isolation, and access controls are continuously trusted; the token is physically secured; repository write credentials are constrained; operators accept that any process able to reach the token can request decryptions and signatures.

This profile protects identity-key export and keeps repository-only attackers from decrypting. It does **not** protect against compromise of the automation host, theft of an attached usable token, or silent mutations by local malware. It is therefore outside the high-security confidentiality profile and should not be represented as equivalent to interactive user presence.

## Recovery and rollback assumptions

Before important use, commission and test a second owner identity kept separately. Commissioning proves fresh signing, X25519 agreement, epoch-key unwrap, and snapshot decryption. Recovery protects against loss of one identity, not against collusion, simultaneous loss, stale backups that omit accepted events, or compromise of both owners.

The repository-local accepted-event checkpoint is useful only while that local ref remains trustworthy. The YubiKey checkpoint is stronger only when its management credential is not available to the repository attacker and its object update is reliable. Touch ID checkpoints live in the login Keychain and are not an independent hardware rollback anchor.

Because the current hardware checkpoint is membership-only, the repository-local checkpoint is what detects omission of already accepted mutations. Copying only `refs/vaults/*` to a new machine does not copy that local trust history.

## Metadata and cryptographic scope

Encrypted payloads conceal secret keys/names, types, values, and snapshots. The format exposes the vault identifier, event type, membership epoch/context, mutation parent hashes, ciphertext lengths, author signing public key, member public keys and roles in membership events, signatures, and event-set/Git metadata.

The v1 format and domain separation are prototype interfaces until format review and golden vectors are complete. Security claims assume correct, nonce-safe implementations of the selected primitives, secure randomness, authentic identity commissioning, and uncompromised private keys.