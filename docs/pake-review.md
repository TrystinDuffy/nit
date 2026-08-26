# PAKE integration review

## Decision

`git-vault` uses `opaque-ke` 3.0 rather than the RustCrypto `spake2` crate.

Reasons:

- OPAQUE is an augmented PAKE designed to avoid a public offline password verifier.
- The `opaque-ke` implementation reports an independent NCC Group audit of an earlier release, with the resulting fixes incorporated by release 1.2.
- Version 3.0 is stable and supports the project's Rust toolchain.
- The reviewed stable SPAKE2 crate explicitly states that it has not received an independent third-party audit; its newer release is pre-release.

Version 3 of `opaque-ke` follows the OPAQUE draft lineage rather than claiming byte compatibility with a final RFC profile. The exact crate version and canonical outer event encoding are therefore protocol-versioned and locked.

## Git transcript

The transport is an asynchronous, attacker-writable Git event log. The implemented exchange is:

1. `CreateInvitation` — trusted owner event containing the OPAQUE password file and an epoch-encrypted `ServerSetup`.
2. `ProposeUser` start — signed but inert requester event containing OPAQUE `CredentialRequest`.
3. `InvitationResponse` — trusted owner event containing `CredentialResponse` and epoch-encrypted serialized `ServerLogin` state.
4. `ProposeUser` final — signed but inert requester event containing OPAQUE `CredentialFinalization` and an immutable reference to the response.
5. `MembershipEpoch` — trusted owner event referencing the exact final proposal and containing admission key confirmation.
6. Requester confirmation — local verification of the exact admission epoch before the hardware checkpoint is accepted.

Requester `ClientLogin` continuation state is stored only through a local Git object referenced by:

```text
refs/vault-onboarding/<vault>/<proposal-event-hash>
```

These refs are never pushed by `git-vault`. The phrase itself is never stored.

## Binding

OPAQUE's context binds:

- vault ID;
- invitation ID;
- trusted invitation event hash;
- requester proposal-start event hash;
- proposed Ed25519 key;
- proposed X25519 key.

The final membership event contains an HMAC under the OPAQUE session key over a domain-separated digest of:

- vault ID;
- parent trusted-state hash;
- immutable final proposal hash;
- complete new membership epoch excluding the confirmation field itself.

This gives the requester explicit confirmation of the exact admission result rather than merely observing its identity somewhere in an attacker-controlled Git log.

## Repository attacker

A repository writer can append arbitrary credential requests, fake invitations, responses, and finalizations. They cannot make an untrusted invitation active, replace the parameters of a trusted owner event, complete OPAQUE without an online phrase guess, or make a proposal trusted without an owner-signed membership epoch.

Public password files and PAKE transcripts do not act as offline phrase verifiers under OPAQUE's security model. Each active attempt still creates bounded log traffic, so event, proposal, and invitation limits remain necessary.

## Tests

The implementation tests:

- correct phrase completion;
- wrong phrase failure;
- equal client/server session keys;
- exact invitation/identity/response binding;
- proposal inertia before owner admission;
- owner admission referencing the exact final proposal;
- admission confirmation under the OPAQUE session key;
- local continuation-state Git refs.
