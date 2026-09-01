# git-vault

`git-vault` is an append-only, Git-native, hardware-backed secret vault. When installed as `git-vault`, Git discovers it as a subcommand:

```sh
git vault        # repository vault manager
git vault prod   # open one vault directly
```

Running `git vault` without a name lists every vault in the repository. The manager can open a vault, create another, or nuke the selected local vault. Its keybindings are:

```text
<j>/<k> select  <Enter> open  <n> new  <d> nuke local  <q> quit
```

The interactive vault TUI derives a verified trusted projection, unlocks the current membership epoch with a YubiKey, and provides the familiar secret workflow:

```text
<j>/<k> select  <n> new  <e> edit  <d> delete
<r> reveal      <y> output  <a> access  <q> quit
```

Successful secret edits immediately append immutable, signed events.

> **Early security prototype:** deterministic trusted replay, encrypted mutations, Git event-set merging, persistent YubiKey membership checkpoints, Ed25519/X25519 hardware identities, and physical-presence onboarding are implemented and tested. The YubiKey checkpoint object still needs broader power-loss/endurance testing. Do not use this as the only copy of important secrets.

## Storage model

Each vault is stored independently through Git objects and its own custom ref, so one repository may contain many vaults:

```text
refs/vaults/prod
refs/vaults/staging
refs/vaults/personal
```

The ref points to a commit whose `vault.log` blob is a bounded, canonical set of immutable signed events. Event identity is the event hash; physical record ordering is irrelevant. It is not a worktree file. `git-vault` does not create `.nit` files and does not write arbitrary mutable files under `.git`.

Additional refs are isolated by purpose:

```text
refs/vault-remotes/<remote>/<vault>   fetched, untrusted remote state
refs/vault-local/<vault>              local freshness checkpoint object
```

Git stores, synchronizes, and retains history. Git commits, authors, timestamps, and ancestry do not decide event authorization.

Nuking through the manager removes the selected vault's local `refs/vaults/*`, freshness, and staged remote refs. It does not delete a remote repository's vault ref, and unreachable Git objects may remain recoverable until Git garbage collection. This is ref deletion, not guaranteed forensic erasure.

## Trust model

Anyone who can write Git objects may append candidate events. Every client independently computes the trusted projection:

```text
untrusted event set
    -> bounded canonical parsing
    -> Ed25519 signature verification
    -> parent_trust_hash matching
    -> authorization under the previously trusted membership
    -> derived trusted state
```

The code distinguishes:

- **Structurally valid:** canonical fields and lengths are valid and the Ed25519 signature verifies.
- **Trusted event:** the event extends the current trust hash and its signer was authorized for that event type by the previous trusted state.

Structurally valid but unauthorized events remain inert. A removed member can continue appending mathematically valid signatures, but those events cannot extend the trusted state.

Every trusted child binds the logical state it intends to extend:

```text
Hnext = SHA256("git-vault/trust/v1" || Hcurrent || event_hash)
```

If multiple authorized children target the same trusted hash, replay stops and reports a fork. V1 does not silently select or merge one branch.

## Membership epochs

The current membership epoch contains:

- trusted member names, roles, Ed25519 keys, and X25519 keys;
- one random epoch key wrapped independently to each member;
- an authenticated encrypted snapshot of current typed values.

Ordinary edits append an encrypted `Mutation` under the current epoch key. The encrypted plaintext contains the operation, secret name, value type, and value; public events reveal only the epoch number, nonce, and ciphertext. Edits do not re-encrypt the whole vault.

A membership transition creates a fresh epoch key and a fresh encrypted snapshot. A new member can decrypt the current logical state without receiving old epoch keys. A removed member receives no new key. Historical access cannot be revoked.

Capabilities are intentionally minimal:

```text
member   read and write secrets
owner    read and write secrets, plus manage membership
```

Every trusted member is a secret reader/writer. Multiple owners are supported.

## Hardware identity

Each provisioned YubiKey uses a permanent public-key pair:

```text
PIV slot 82   X25519 encryption/key agreement
PIV slot 83   Ed25519 event signing
```

Private keys remain on the device. Normal provisioning uses PIN-once with touch-always for X25519 and touch-cached for Ed25519. Identity sessions keep the replay and crypto code independent of the local key mechanism.

PIN and touch policies are immutable after PIV key generation. An explicit destructive replacement can generate both keys with `PIN never` and `touch never`:

```sh
git vault <vault> destroy-identity --identity <serial>
```

The command requires typing `DESTROY <serial>` and authenticating with the PIV management key. It destroys the old permanent identity and clears its hardware checkpoints; existing vault refs are deliberately left untouched. Any vault that trusted only the destroyed identity becomes inaccessible and must be recovered by another member or nuked and recreated. With neither PIN nor touch, any local process can use the connected YubiKey to decrypt and sign.

On macOS, `--identity touchid` creates or opens one Ed25519/X25519 identity stored in the login Keychain. The CLI requests Touch ID through LocalAuthentication before loading the private keys, but unlike a YubiKey or a future Secure Enclave implementation, those keys enter application memory while the vault is open.

This easy path uses an application-enforced biometric check because biometric Keychain ACLs require signing entitlements unavailable to a plain `cargo install` binary. A local process with independent access to the user's unlocked Keychain can bypass that check. The public identity and rollback checkpoints are separate Keychain items so identities can be listed without a biometric prompt; those checkpoints detect ordinary rollback but are not independent hardware anchors.

The stable member identity is the Ed25519/X25519 public-key pair—not a serial number, Git identity, or certificate fingerprint. YubiKey serials and `touchid` are only local locators.

The current signed event format carries only the permanent Ed25519/X25519 public-key pair; it does not reserve an unused certificate field or define a general PKI.

## Usage

Run inside a Git working tree. Creating a missing vault provisions/selects an identity and writes `refs/vaults/<name>`:

```sh
git vault prod
```

With multiple identities:

```sh
git vault prod --identity 33127878
git vault prod --identity touchid
```

Stable commands are available for automation:

```sh
git vault prod list
git vault prod get TOKEN
printf '%s' "$TOKEN" | git vault prod set TOKEN --stdin
git vault prod set PORT --type number
git vault prod set ENABLED --type boolean
git vault prod set KEY_BYTES --type bytes
git vault prod delete TOKEN
git vault prod members
git vault prod add-member --name Bob --new-identity <serial|touchid> --capability member
git vault prod add-member --name Bob --new-identity <serial|touchid> --capability owner
git vault prod remove-member <name-or-fingerprint>
git vault prod set-role <name-or-fingerprint> member
git vault prod verify
```

Typed values currently support:

```text
text
number
boolean
bytes       hexadecimal command input/output
```

Secret prompts use the controlling terminal. `--stdin` is an explicit pipeline opt-in.

## Synchronization

Custom refs are not included by ordinary branch fetch/push defaults. Use:

```sh
git vault prod push origin
git vault prod fetch origin
```

Push never forces the remote vault ref. Fetch first writes only to:

```text
refs/vault-remotes/origin/prod
```

The fetched event set is parsed and unioned with the local set by event hash. The merged set is replayed, forks and rollback are checked, and a two-parent Git commit preserves both local and remote histories. A remote omission cannot delete a local event.

Never configure `refs/vault-local/*` for pushing. It contains the local freshness checkpoint.

## Physical-presence membership management

Adding a member is synchronous: an existing owner key and the new key must both be connected to the same machine. The new key is provisioned if needed, proves possession of its Ed25519 signing key, and unwraps the next X25519-wrapped epoch key before admission. The owner then signs one `MembershipEpoch` event containing the exact new identity, name, capability, encrypted snapshot, and wrapped epoch keys.

The membership event is committed only after both local key proofs succeed. The owner and new key checkpoints are then written and reread. If the Git commit succeeds but either checkpoint update fails, the member is already admitted; reconnect the affected key and reopen the vault. Opening verifies the committed lineage and retries any missing or older checkpoint rather than creating another membership event.

Trusted replay authorizes the change from the existing owner's signature. Physical presence is an enforced local interaction, not an asynchronous event transcript.

## Rollback anchors

Two independent mechanisms are designed:

- `refs/vault-local/<vault>` detects ordinary trusted-state rollback on a machine that has previously accepted a newer state.
- A management-key-authenticated YubiKey trust object anchors the newest accepted membership epoch outside rollbackable Git. Touch ID identities instead use the weaker local Keychain checkpoint described above.

The YubiKey stores up to 16 canonically ordered vault-name/checkpoint records in PIV object `5FC10E`; it never silently evicts one. Creating a vault or accepting a newer membership epoch requires persisting and rereading this checkpoint. Failure aborts acceptance with a prominent error. This binds a familiar vault name to its permanent vault ID, membership event, and trust hash, so a replacement repository cannot silently establish another Genesis for that name.

The management key is requested through the controlling terminal for checkpoint updates and is never cached or embedded. The object layout and remaining hardware-testing caveats are documented in [`docs/yubikey-checkpoint-feasibility.md`](docs/yubikey-checkpoint-feasibility.md).

## Binary format and limits

The current prototype format uses `GVLOG005`/`GVEVT005`. The explicit binary codec is versioned, length-delimited, canonical, and independently frames each event. Prototype formats are not migrated or accepted as legacy input.

```text
log magic
event length
event magic + version
vault ID + event type
parent trust hash + author signing key
bounded canonical payload
Ed25519 signature
```

Unknown event types, trailing fields, truncation, malformed payloads, invalid signatures, and oversized records are rejected or diagnosed without granting trust. Event hashes are the immutable set identity.

Hard limits include:

- 64 MiB complete event collection;
- 20 MiB event;
- 16 MiB value/snapshot;
- 64 members;
- bounded encrypted mutations and names.

A writer can still cause storage or download denial of service. Cryptography makes unauthorized data inert, not free.

## Development

Rust 1.87 is pinned in `mise.toml`.

```sh
mise install
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- prod --help
cargo build --release
./install
cargo check --manifest-path fuzz/Cargo.toml

# Optional parser fuzzing (requires cargo-fuzz)
cargo fuzz run event_log
```

`./install` installs:

```text
~/.local/bin/git-vault
```

Ensure that directory is on `PATH` so `git vault` can discover it.

Nix users can use:

```sh
nix develop
nix build
nix run . -- prod --help
nix flake check
```

Linux builds require PC/SC development libraries, and runtime YubiKey access requires `pcscd`/CCID support. YubiKey firmware 5.7.4 or newer and a non-FIPS model are required for PIV Ed25519/X25519 and enforceable key-policy metadata.

## Security-critical modules

```text
src/cli.rs                 stable Git-subcommand CLI
src/git.rs                 isolated Git plumbing and CAS refs
src/event.rs               canonical events and bounded stream parser
src/state.rs               pure trusted replay, authorization, forks, rollback checks
src/crypto.rs              epoch wrapping, snapshots, typed value AEAD
src/identity.rs            hardware identity and session types
src/manager.rs             repository-level vault list/create/nuke TUI
src/backends/yubikey.rs    PC/SC and PIV implementation
src/backends/touch_id.rs   macOS Touch ID-gated Keychain identity
src/backends/test_identity.rs software identity for deterministic tests
src/runtime.rs             command orchestration and immediate event appends
src/terminal.rs            terminal lifecycle and identity chooser
src/tui.rs                 interaction over an in-memory trusted projection
fuzz/fuzz_targets/event_log.rs bounded parser fuzz target
```

The core rule is:

> Given the trusted state immediately before this event, was this signer authorized to make this exact change?
