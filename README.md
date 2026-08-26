# git-vault

`git-vault` is an append-only, Git-native, hardware-backed secret vault. When installed as `git-vault`, Git discovers it as a subcommand:

```sh
git vault prod
```

The interactive TUI derives a verified trusted projection, unlocks the current membership epoch with a YubiKey, and provides the familiar secret workflow:

```text
<j>/<k> select  <n> new  <e> edit  <d> delete
<r> reveal      <y> output  <a> access  <q> quit
```

Successful secret edits immediately append immutable, signed events.

> **Early security prototype:** the event log, trusted replay, epoch encryption, Git plumbing, fork detection, Ed25519/X25519 hardware identities, and audited OPAQUE onboarding are implemented and tested. X.509 identity envelopes and persistent YubiKey membership checkpoints remain incomplete. Do not use this as the only copy of important secrets.

## Storage model

A vault is stored only through Git objects and a custom ref:

```text
refs/vaults/prod
```

The ref points to a commit whose `vault.log` blob is a bounded, canonical, append-only binary event stream. It is not a worktree file. `git-vault` does not create `.nit` files and does not write arbitrary mutable files under `.git`.

Additional refs are isolated by purpose:

```text
refs/vault-remotes/<remote>/<vault>   fetched, untrusted remote state
refs/vault-local/<vault>              local freshness checkpoint object
refs/vault-onboarding/<vault>/<event> requester-only OPAQUE continuation state
```

Git stores, synchronizes, and retains history. Git commits, authors, timestamps, and ancestry do not decide event authorization.

## Trust model

Anyone who can write Git objects may append candidate events. Every client independently computes the trusted projection:

```text
raw event log
    -> bounded canonical parsing
    -> Ed25519 signature verification
    -> parent_trust_hash matching
    -> authorization under the previously trusted membership
    -> derived trusted state
```

The code uses three distinct validation levels:

- **Structurally valid:** canonical fields and lengths are valid and the Ed25519 signature verifies.
- **Invitation-authenticated proposal:** a proposal has additionally completed the audited OPAQUE exchange and explicit key confirmation.
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

Ordinary `Put` and `Delete` events use the current epoch key. They do not re-encrypt the whole vault.

A membership transition creates a fresh epoch key and a fresh encrypted snapshot. A new member can decrypt the current logical state without receiving old epoch keys. A removed member receives no new key. Historical access cannot be revoked.

Current roles are intentionally minimal:

```text
reader
owner
```

V1 currently permits only owners to append trusted state changes.

## Hardware identity

Each provisioned YubiKey uses a permanent public-key pair:

```text
PIV slot 82   X25519 encryption/key agreement
PIV slot 83   Ed25519 event signing
```

Private keys remain on the device. PIN verification happens once per application session. X25519 unlock requires touch; newly provisioned Ed25519 signing keys use YubiKey's cached-touch policy so a burst of event appends does not require a touch for every event. Application code uses generic identity traits so software identities can exercise the security-critical replay and crypto code in tests.

The stable member identity is the Ed25519/X25519 public-key pair—not a serial number, Git identity, or certificate fingerprint. YubiKey serials are only local backend locators.

A future PIV-native self-signed X.509 envelope may bind the two public keys and protocol metadata. It will not become a vault CA, revocation system, OCSP hierarchy, or general PKI.

## Usage

Run inside a Git working tree. Creating a missing vault provisions/selects an identity and writes `refs/vaults/<name>`:

```sh
git vault prod
```

With multiple identities:

```sh
git vault prod --identity yubikey:33127878
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
git vault prod invite --minutes 30 --words 4
git vault prod request-access <invitation> --name Bob
git vault prod respond <proposal-start>
git vault prod continue-request <proposal-start>
git vault prod approve <final-proposal>
git vault prod confirm-access <final-proposal>
git vault prod remove-member <name-or-fingerprint>
git vault prod set-role <name-or-fingerprint> reader
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

The fetched log is parsed, signatures and authorization are replayed, forks and local rollback are checked, and only then is `refs/vaults/prod` advanced with a compare-and-swap ref update.

Never configure `refs/vault-local/*` or `refs/vault-onboarding/*` for pushing. They contain local freshness and requester continuation state, respectively.

## Invitations and membership management

The binary event model includes immutable `CreateInvitation`, `InvitationResponse`, `CloseInvitation`, and staged `ProposeUser` records. `git-vault` uses `opaque-ke` 3.0 with Ristretto255, TripleDH, and Argon2. The implementation lineage was independently audited by NCC Group; the older unaudited SPAKE2 crate was not selected. The review is recorded in [`docs/pake-review.md`](docs/pake-review.md).

The asynchronous exchange is:

1. An owner appends a trusted invitation containing an OPAQUE password file and an epoch-encrypted server setup.
2. The requester appends a signed, inert OPAQUE credential request and retains continuation state only under `refs/vault-onboarding/*`.
3. An owner appends a trusted OPAQUE server response with epoch-encrypted server state.
4. The requester appends the OPAQUE finalization. The owner verifies key confirmation before approval.
5. The owner appends a membership epoch referencing the exact final proposal.
6. The requester verifies an admission confirmation bound to the exact epoch before accepting/checkpointing membership.

When participants use different clones, they run `git vault <name> push`/`fetch` between these append steps. The PAKE protocol itself is transport-independent. In interactive mode, selecting an untrusted or provisionable YubiKey starts or resumes this invitation workflow instead of attempting to unlock the vault as a trusted member.

OPAQUE context and admission confirmation bind:

```text
vault ID
invitation ID
proposed Ed25519/X25519 identity
new membership epoch
trusted membership hash
```

A proposal remains inert until an existing owner signs the membership epoch that references that exact immutable final proposal. Wrong phrases and repository parameter substitution fail OPAQUE confirmation without creating a public offline phrase verifier.

## Rollback anchors

Two independent mechanisms are designed:

- `refs/vault-local/<vault>` detects ordinary trusted-state rollback on a machine that has previously accepted a newer state.
- A YubiKey trust record will anchor the newest accepted membership epoch outside rollbackable Git.

The local freshness ref is implemented. The generic hardware checkpoint interface and replay validation are implemented; persistent YubiKey checkpoint storage is not yet implemented, and vault creation reports that limitation explicitly. PIV object constraints and the required prototype are documented in [`docs/yubikey-checkpoint-feasibility.md`](docs/yubikey-checkpoint-feasibility.md).

A fresh clone has neither checkpoint. It can verify signatures and authorization from Genesis but cannot independently know whether the repository omitted a newer valid suffix. This limitation is fundamental and documented rather than hidden.

## Binary format and limits

The current prototype format uses `GVLOG002`/`GVEVT002`. The explicit binary codec is versioned, length-delimited, canonical, and independently frames each event. Prototype formats are not migrated or accepted as legacy input.

```text
log magic
event length
event magic + version
vault ID + event ID + type
parent trust hash + author signing key
bounded canonical payload
Ed25519 signature
```

Unknown event types are structurally parseable but inert. Trailing fields, truncation, duplicate event IDs, malformed keys, invalid signatures, and oversized records are rejected or diagnosed without granting trust.

Hard limits include:

- 64 MiB complete log;
- 20 MiB event;
- 16 MiB value/snapshot;
- 64 members;
- 32 active invitations;
- 128 pending proposals;
- bounded names, keys, PAKE messages, and certificates.

A writer can still cause storage or download denial of service. Cryptography makes unauthorized data inert, not free.

## Development

Rust 1.87 is pinned in `mise.toml`.

```sh
make setup
make check
make run ARGS='prod --help'
make release
make install-user

# Optional parser fuzzing (requires cargo-fuzz)
cargo fuzz run event_log
```

`make install-user` installs:

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

Linux builds require PC/SC development libraries, and runtime YubiKey access requires `pcscd`/CCID support. YubiKey firmware 5.7 or newer and a non-FIPS model are required for PIV Ed25519/X25519.

## Security-critical modules

```text
src/cli.rs                 stable Git-subcommand CLI
src/git.rs                 isolated Git plumbing and CAS refs
src/event.rs               canonical events and bounded stream parser
src/state.rs               pure trusted replay, authorization, forks, rollback checks
src/crypto.rs              epoch wrapping, snapshots, typed value AEAD
src/identity.rs            backend-neutral hardware identity traits
src/invitation.rs          audited OPAQUE onboarding and admission confirmation
src/backends/yubikey.rs    PC/SC and PIV implementation
src/backends/test_identity.rs software identity for deterministic tests
src/runtime.rs             command orchestration and immediate event appends
src/terminal.rs            terminal lifecycle and identity chooser
src/tui.rs                 interaction over an in-memory trusted projection
fuzz/fuzz_targets/event_log.rs bounded parser fuzz target
```

The core rule is:

> Given the trusted state immediately before this event, was this signer authorized to make this exact change?
