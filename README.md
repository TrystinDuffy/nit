# nit

`nit` is a tiny, single-executable secret vault backed by a YubiKey 5. It has one normal command shape:

```text
nit <file> [-k <keys>]
```

Opening a vault starts a terminal interface for creating, editing, deleting, and revealing named secrets. The optional `-k` argument feeds keys into the same state machine for automation.

> **Alpha security software:** the implementation has unit tests and uses standard constructions, but it has not received an independent security audit. Do not make it the only copy of irreplaceable credentials yet.

## Requirements

- YubiKey 5 firmware 5.7.0 or newer with PIV enabled.
- A non-FIPS model: Yubico does not allow X25519 in the PIV application on FIPS 140-3 capable devices.
- The smart-card/CCID support included with the operating system. On Linux, this normally means `pcscd`; macOS and Windows provide a system smart-card service.

Yubico documents X25519 as PIV algorithm `E1` and its firmware/model restrictions in the [YubiKey Technical Manual](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/webdocs.pdf).

## Build

```sh
cargo build --release
install target/release/nit /usr/local/bin/nit
```

The deliverable is the single `target/release/nit` executable. Rust packages in `Cargo.toml` are compiled into that executable; users do not install them. `nit` does not execute or require `ykman`, `age`, `openssl`, a YubiKey plugin, a language runtime, or companion data files.

Like every application that talks to a smart card, it calls the operating system's smart-card interface. That system interface is the sole runtime boundary; `nit` does not bundle its own USB kernel driver.

## First use

Insert one YubiKey and run:

```sh
nit secrets.nit
```

When the file does not exist, `nit` examines retired PIV slot `82`:

- If slot `82` already contains an X25519 key, `nit` reuses it.
- If it contains any other key type, `nit` stops. It never overwrites existing key material.
- If it is empty, `nit` asks for the PIV management key and generates an X25519 key with PIN policy `once` and touch policy `always`.

Press Enter at the management-key prompt to use Yubico's factory management key. A custom management key is entered as hexadecimal. Key generation requires firmware 5.7+; the private key never leaves the YubiKey.

Losing or deleting the PIV private key makes the vault permanently unreadable. Slot `82` must be backed up by your own recovery strategy if the data cannot be recreated.

## Interactive keys

| Key | Action |
|---|---|
| `j` / Down | Select next secret |
| `k` / Up | Select previous secret |
| `n` | Create a secret |
| `e` | Replace the selected value |
| `d` | Delete the selected secret after confirmation |
| `r` | Reveal or hide the selected value |
| `y` | Queue the selected value for stdout after exit |
| `q` | Quit |
| Esc | Cancel the current prompt; quit from the list |

Every successful creation, edit, or deletion is encrypted and atomically saved immediately. Quitting is not required to commit a change.

## Key automation

Literal characters are typed as-is. These named tokens are supported:

```text
<enter>  <esc>  <up>  <down>  <backspace>
<tab>    <space> <lt>  <stdin>
```

Create two values:

```sh
nit secrets.nit -k 'nFOO<enter>bar<enter>nBAZ<enter>qux<enter>q'
```

Output the first selected value:

```sh
nit secrets.nit -k 'yq'
```

Do not place real secret values directly in `-k`: command arguments can appear in shell history and process listings. Use `<stdin>` so the value is read from standard input without being reinterpreted as keys:

```sh
printf '%s' "$TOKEN" |
  nit secrets.nit -k 'nGITHUB_TOKEN<enter><stdin><enter>q'
```

PIN and management-key prompts still read securely from the controlling terminal when stdin supplies a value.

## Cryptographic design

The YubiKey does not encrypt the vault contents directly. `nit` uses envelope encryption:

1. Serialize the complete name/value map with strict size and duplicate checks.
2. Generate a fresh random 256-bit file key and encrypt the map with XChaCha20-Poly1305.
3. Generate an ephemeral X25519 key and ask the recipient public key to perform ECDH.
4. Derive a wrapping key with HKDF-SHA256 using both public keys as the salt.
5. Wrap the file key with XChaCha20-Poly1305.
6. Authenticate the version, YubiKey serial hint, slot, public keys, nonces, and wrapped key as associated data.

On decryption, `nit` verifies the PIV PIN and asks the YubiKey to perform the private X25519 operation. The valuable private key remains non-exportable. Metadata such as the serial number is a device-selection hint and is not treated as secret.

The file is a bounded binary format beginning with `NITVLT01`. It is intentionally not compatible with SOPS or age in version 1. This MVP supports one recipient per vault and encrypts the whole vault rather than individual fields.

Secret values, decrypted payload buffers, derived keys, management credentials, and file keys are zeroed when their owning buffers are dropped. Operating systems, terminal emulators, allocators, and crash dumps can still copy process memory; memory zeroization is defense in depth, not a guarantee that plaintext never existed elsewhere.

## Repository safety

Encrypted `.nit` files are intended to be committed. Plaintext export is explicit through reveal or `y`; redirect it carefully. A typical repository might contain:

```text
secrets/
  production.nit
  staging.nit
```

No plaintext temporary file is used by the built-in interface.

## License

MIT

