# YubiKey membership checkpoint

## Implemented object

`git-vault` stores its external rollback anchor in PIV object `5FC10E` (`RETIRED2`). The object is raw application data rather than an X.509 certificate. Current event identities are only the permanent slot-83 Ed25519 and slot-82 X25519 public-key pair; no unused certificate field is carried in the signed event format.

The object header binds both permanent public keys and contains at most 16 canonically ordered records. Each record contains:

```text
vault name                   1–64 bytes
vault ID                         32 bytes
membership epoch                  8 bytes
membership event hash            32 bytes
trusted trust hash               32 bytes
```

Vault name is included so a fresh clone opening a familiar name cannot silently substitute a different vault ID. A full object causes a hard error; records are never silently evicted.

## Write authorization

PIV `PUT DATA` requires management-key authentication. Updating a checkpoint therefore explicitly prompts on the controlling terminal for the management key; Enter selects the factory default. The key is zeroized after use and is never embedded, stored, or cached.

After writing, `git-vault` rereads and canonically decodes the object. A mismatch is fatal.

## Acceptance rule

After verifying a vault against any existing hardware record, the client compares the newest trusted membership epoch with the device checkpoint. Before treating a newer epoch as accepted, it must persist and reread the new checkpoint. This applies to:

- vault creation;
- owner admission/removal/capability changes;
- ordinary members observing a membership transition created elsewhere;
- requester admission confirmation.

A failed update is a hard, prominent error rather than a silently ignored warning.

## Remaining hardware validation

The protocol behavior is implemented and parser/round-trip tested, but production claims still require physical validation across supported YubiKey models:

1. Measure reliable object capacity on each supported firmware line.
2. Exercise interrupted `PUT DATA` operations and characterize power-loss behavior.
3. Confirm write-endurance expectations for realistic membership churn.
4. Verify management-key algorithms other than the factory-default TDES configuration.
5. Test full 16-vault objects and explicit capacity failure.

Firmware 5.7.4 or newer and readable policy metadata are required. Normal provisioning uses:

```text
slot 82 X25519   PIN once; touch always
slot 83 Ed25519  PIN once; touch cached
```

A deliberately destructive identity-replacement command can instead generate both slots with `PIN never` and `touch never`. This preserves non-exportability but removes user-presence and user-verification protections while the token is connected.
