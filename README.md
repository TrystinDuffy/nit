# nit

`nit` is a tiny, single-executable secret vault backed by YubiKey 5. A vault is opened with one command:

```text
nit [options] <file> [command]
```

With no command, the terminal interface manages secrets, recipients, invitation slots, and access requests. Explicit subcommands provide stable automation without replaying UI keystrokes.

> **Alpha security software:** `nit` uses standard age encryption and has unit tests, but it has not received an independent security audit. Do not make it the only copy of irreplaceable credentials yet.

## Requirements

- YubiKey 5 firmware 5.7.0 or newer with PIV enabled.
- A non-FIPS model: Yubico does not allow X25519 in the PIV application on FIPS 140-3 capable devices.
- The smart-card/CCID support included with the operating system. On Linux, this normally means `pcscd`; macOS and Windows provide a system smart-card service.

Yubico documents X25519 as PIV algorithm `E1` and its firmware/model restrictions in the [YubiKey Technical Manual](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/webdocs.pdf).

## Development workflow

### Mise

The repository pins Rust 1.87 in `mise.toml`. Bootstrap once, then use Make:

```sh
make setup
make check
```

The normal edit/test loop is:

```sh
make fmt
make check
make run ARGS='--help'
make run ARGS='path/to/secrets.nit'
```

`make build` creates `target/debug/nit`. `make check` runs the formatting check, unit tests, and Clippy with warnings denied. Run `make help` for every target.

If Rust is already managed without Mise, the Makefile uses the `cargo` and `rustc` on `PATH`. They can also be overridden explicitly:

```sh
make check CARGO=/path/to/cargo RUSTC=/path/to/rustc
```

### Nix

The flake supplies Rust 1.87, `pkg-config`, and PC/SC development libraries on Linux:

```sh
nix develop       # enter the development shell
nix build         # build ./result/bin/nit
nix run . -- --help
nix flake check   # build and run package tests
```

The host smart-card service still needs to be running when nit accesses a YubiKey.

### Release builds and archives

```sh
make release       # build target/release/nit
make dist          # build dist/nit-<version>-<host>.tar.gz
make ci            # run all checks and create the dist tarball
```

`make dist` packages the optimized executable with `README.md` and `LICENSE`, then prints its path. The resulting executable is host-specific and still uses the operating system PC/SC interface.

For a project release:

1. Update `version` in `Cargo.toml` and refresh `Cargo.lock` with `cargo check`.
2. Run `make ci` and exercise the physical YubiKey unlock/request flow.
3. Commit, create a signed `v<version>` Git tag, and push it.
4. Run `make dist` and attach the archive to the GitHub release.

The crate has `publish = false`; releases are executable archives rather than crates.io publications.

### Install

Install for the current user without privilege escalation:

```sh
make install-user
# installs $HOME/.local/bin/nit
```

Install system-wide:

```sh
sudo make install
# installs /usr/local/bin/nit
```

Packaging systems can stage an installation without privilege escalation:

```sh
make install DESTDIR="$pkgdir" PREFIX=/usr
```

All Rust dependencies, including age, are compiled into the executable. Users do not install the `age` command, `ykman`, OpenSSL, a YubiKey plugin, or a language runtime. The operating system smart-card interface is the sole runtime boundary.

## First use

Insert one YubiKey and run:

```sh
nit secrets.nit
```

For retired PIV slot `82`, nit will:

- Reuse an existing X25519 key.
- Refuse to overwrite any other key type.
- Otherwise ask for the PIV management key and generate an X25519 key with PIN policy `once` and touch policy `always`.

Press Enter at the management-key prompt to use Yubico's factory management key. A custom management key is entered as hexadecimal. The private key never leaves the YubiKey.

A generated PIV key cannot be exported or backed up. Open an invitation and authorize at least one additional YubiKey if the vault needs recovery.

### Identity backends and multiple devices

Nit's vault, crypto, UI, and command layer operate on backend-neutral identity records. The current `yubikey` backend inspects the serial number, slot type, and X25519 public key before asking for a PIN or touch:

- One eligible identity is selected automatically.
- Multiple usable identities always open an interactive `j`/`k` selector, including when only one is currently authorized for the vault.
- When opening an existing vault, the selector marks each identity as authorized or not authorized.
- Creating a vault or requesting access shows only identities that are ready or can be provisioned.
- A YubiKey with a non-X25519 slot 82 is displayed as unavailable and is never overwritten.

For commands, or to bypass the selector, use the stable `backend:locator` identity selector:

```sh
nit --identity yubikey:33127878 secrets.nit
nit --identity yubikey:33127878 secrets.nit list
```

Commands require `--identity` when multiple eligible identities are discovered so automation remains deterministic.

`src/identity.rs` defines backend-neutral discovery, provisioning, matching, and unlock traits plus the generic authorized-recipient record. Implementations live under `src/backends/`; PIV/APDU details are isolated in `src/backends/yubikey.rs`. A future macOS backend can use LocalAuthentication and a Keychain access-control policy to gate an age identity with Touch ID. Touch ID is an authorization mechanism rather than an age key itself, and no YubiKey fields need to leak into the vault format or application logic.

## Secret keys

| Key | Action |
|---|---|
| `j` / Down | Select next secret |
| `k` / Up | Select previous secret |
| `n` | Create a secret |
| `e` | Replace the selected value |
| `d` | Delete the selected secret after confirmation |
| `r` | Reveal or hide the selected value |
| `y` | Queue the selected value for stdout after exit |
| `a` | Manage recipients, invitations, and requests |
| `q` | Quit |
| Esc | Cancel the current prompt; quit from the list |

Every successful change is encrypted and atomically saved immediately.

## Access keys

Press `a` from the secret list.

| Key | Action |
|---|---|
| `j` / Down | Select next access record |
| `k` / Up | Select previous access record |
| `n` | Open an invitation slot |
| `e` | Rename the selected recipient |
| `d` | Remove the selected recipient after confirmation |
| `a` | Approve the selected request |
| `x` | Reject and remove the selected request |
| `c` | Close the selected invitation |
| Esc / `q` | Return to secrets |

Recipient names are encrypted, authenticated display metadata. Authorization always uses the canonical X25519 public key and displayed fingerprint, never the friendly name. Nit refuses to remove the final recipient. Removing any other recipient affects newly saved versions only; that key can still decrypt historical versions it already obtained from Git.

## Invitation slots

An authorized user opens a slot with `a`, then `n`. Nit asks for:

- A lifetime in minutes; the default is 30 and the maximum is seven days.
- A phrase length from four to six words; the default is four.

Words are selected uniformly with the operating-system CSPRNG from the 2048-word BIP-39 English list. They are not wallet mnemonics. Approximate entropy is 44, 55, or 66 bits. Four words plus the memory-hard KDF are the minimum accepted security level.

The requester types the complete phrase on **one line**, with a space between each word, and presses Enter only after the final word. For example, if the owner shares:

```text
canvas oxygen trophy
```

the requester enters exactly `canvas oxygen trophy`, without quotes, commas, an invitation ID, or Enter between words. ASCII hyphens are also accepted in place of spaces.

Each slot is one-use and permits three approval attempts. The phrase authenticates a request only: it never decrypts the vault.

### Git request lifecycle

1. An owner opens an invitation, commits the changed `.nit` file, and pushes it.
2. The owner shares the invitation phrase verbally.
3. The anticipated recipient pulls, opens the same `.nit` file, and selects the invitation.
4. They type all invitation words on one line separated by spaces, press Enter once, and then enter a friendly identity name.
5. Nit adds an encrypted request to that same `.nit` file without changing the encrypted vault payload.
6. The requester commits and pushes the file.
7. An owner pulls, unlocks the vault, and reviews the pending request.
8. Approval adds the new identity, consumes the invitation, reseals the vault to every recipient, and removes the request.
9. The owner commits and pushes; the new recipient pulls and can unlock.

Nit does not execute Git. Repository operations remain explicit.

Expiration is checked against the local clock whenever anyone opens the file. Unauthenticated users cannot submit against an expired slot. When an owner unlocks the vault, nit automatically closes expired invitations, removes their pending requests, reseals the authenticated payload, and atomically saves the cleanup. Git commit timestamps are not trusted proof that a request was made before expiration.

### Invitation tamper resistance

Each invitation derives independent binding and request keys with Argon2id using 64 MiB of memory, three passes, and a salt bound to the vault and invitation IDs. A public HMAC binds the vault ID, invitation ID, expiration, and request-inbox recipient.

Before touching the requester's YubiKey, nit derives the phrase keys and verifies that binding in constant time. A repository writer who substitutes an inbox key or edits invitation metadata gets only a generic “incorrect phrase or tampered repository copy” failure. Owners also compare the public invitation records against the authenticated records after decrypting the vault.

The public binding is necessarily an offline verifier, which is why nit now requires at least four random words and a memory-hard KDF. A request is additionally age-encrypted to the inbox and HMAC-bound to its vault, invitation, recipient, name, and nonce. Every failed owner approval consumes an attempt.

A malicious writer can still delete requests, replay an old unexpired file, or create denial-of-service conflicts. Git review, branch protection, and expiry remain part of the security boundary.

When a recipient is removed, nit rotates the inbox key and closes every invitation and pending request. This prevents former recipients who retained an old inbox key from reading future requests.

## Command automation

Automation uses explicit commands rather than replaying TUI keystrokes:

```sh
nit secrets.nit list
nit secrets.nit get GITHUB_TOKEN
printf '%s' "$TOKEN" | nit secrets.nit set GITHUB_TOKEN --stdin
nit secrets.nit delete GITHUB_TOKEN

nit secrets.nit invite --minutes 30 --words 4
nit secrets.nit invitations
nit secrets.nit recipients
nit secrets.nit requests
nit secrets.nit approve <request-id-prefix>
nit secrets.nit reject <request-id-prefix>
```

An unapproved recipient can submit a request without putting the phrase in process arguments:

```sh
printf '%s\n' 'canvas oxygen trophy velvet' |
  nit --identity yubikey:33127878 secrets.nit request-access <invitation-id> \
    --name 'Alice — Work YubiKey' --phrase-stdin
```

Secret values and phrases default to secure controlling-terminal prompts. `--stdin` and `--phrase-stdin` are explicit opt-ins for pipelines. PIN and management-key prompts always use the controlling terminal.

## Cryptographic design

A file begins with `NITVLT03` and contains two trust domains:

1. An age-encrypted payload containing secrets, approved recipients, friendly names, invitation keys, attempt counters, and the request-inbox private key.
2. Strictly bounded public routing metadata, phrase-authenticated invitations, and age-encrypted access requests.

The vault payload uses standard age X25519 recipient stanzas and age's authenticated streaming payload format. Each approved identity receives the age file key independently. Backends implement discovery, provisioning, recipient matching, and unlock. The YubiKey backend adapts PIV ECDH to the standard age X25519 identity operation; future biometric or platform-key backends can provide the same interface.

The complete `.nit` container is not directly accepted by the age CLI because nit's public invitation and request records wrap the embedded age payload. The age format and primitives are used internally rather than through an external process.

Secret values, decrypted payloads, invitation phrases and keys, PINs, management credentials, ECDH outputs, and file keys are zeroed where their owning Rust buffers permit. Operating systems, terminal emulators, allocators, and crash dumps can still copy process memory; zeroization is defense in depth.

## Repository safety and limitations

Encrypted `.nit` files are intended to be committed. Requests and public invitation metadata reveal no secret values, but they do reveal workflow activity and YubiKey routing metadata.

- Removing a recipient cannot revoke old versions they already obtained from Git history.
- Git rollback cannot be prevented by the vault alone. Signed commits, branch protection, and clients remembering newer generations can help detect it.
- Concurrent modifications to the same binary `.nit` file can conflict and must be resolved by repeating the request against the latest version rather than byte-merging vault files.
- Plaintext export is explicit through reveal or `y`; redirect it carefully.

No plaintext temporary file is used by the built-in interface.

## License

MIT
