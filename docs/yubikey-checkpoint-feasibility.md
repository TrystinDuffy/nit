# YubiKey certificate and membership-checkpoint feasibility

The PIV transport already used by `git-vault` supports the necessary key operations, but standard PIV does not expose a monotonic counter or a general PIN-writable persistent record.

## Certificate envelope

The Ed25519 signing key uses retired slot `83`. Its corresponding PIV certificate object is `5FC10E` (`RETIRED2`). A self-signed certificate stored there can carry:

- the slot's Ed25519 public key;
- a private extension containing the X25519 slot-82 public key;
- a protocol/version identifier;
- optional bounded hardware trust records.

Verification must check the self-signature with the slot-83 public key, exact slot signing-key correspondence, the custom extension encoding, and the X25519 binding. The member identity remains the public-key pair because replacing/updating the certificate must not change identity.

This is an identity envelope only. It does not imply a vault CA, certificate revocation list, OCSP, or X.509 delegation.

## Write authorization and UX constraint

PIV `PUT DATA` writes to certificate/data objects require management-key authentication. PIN verification alone is insufficient. Therefore updating a checkpoint inside the certificate after every membership change would require either:

- prompting for the management key on each membership transition; or
- using a separately protected management-key mechanism whose threat model is explicitly designed.

Silently caching or embedding the management key would defeat the purpose of the out-of-repository anchor. The current backend consequently reports checkpoint persistence as unsupported rather than pretending a local file is hardware state.

## Capacity and multiple vaults

A certificate extension can hold a bounded list of records, but object-size and update limits must be measured on supported YubiKey firmware. The design needs deterministic eviction/full-capacity behavior; evicting a newer vault checkpoint could re-enable rollback for that vault.

A single record is:

```text
vault_id                    32 bytes
membership_epoch             8 bytes
membership_event_hash       32 bytes
trusted_trust_hash          32 bytes
```

Encoding overhead, certificate fields, signatures, and a bounded multi-vault index must also fit.

## Required prototype before enabling

1. Generate Ed25519 in slot 83 and verify raw PIV signatures.
2. Build a minimal DER self-signed certificate using the hardware key.
3. Store/read it through object `5FC10E` with management authentication.
4. Verify all custom bindings independently after reading.
5. Measure maximum reliable object size and write endurance constraints.
6. Test certificate/checkpoint updates across power loss.
7. Decide and document management-key handling and multi-vault capacity.
8. Confirm that an older repository membership state is rejected against the stored record.

Until these tests pass, `IdentitySession::read_trust_record` returns no checkpoint and `write_trust_record` fails explicitly. Local freshness refs remain a separate, weaker rollback signal.
