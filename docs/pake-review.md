# PAKE integration review

## Decision

`git-vault` uses RustCrypto `spake2` 0.4 with its Ed25519-group parameter set and explicit HMAC key confirmation.

The crate states that it has **not** received an independent third-party audit and may not be constant-time. This is a material limitation. `git-vault` remains an early security prototype.

OPAQUE through `opaque-ke` was previously selected because that implementation lineage had received an NCC Group audit. It was removed because its augmented client/server login topology required an additional asynchronous server response and requester finalization. That did not match the required invitation pairing flow.

No custom PAKE primitive is implemented.

## Required exchange

The implemented exchange has three event-producing actions:

1. **Owner invitation:** generates the phrase and a SPAKE2 role-B message.
2. **Requester phrase proof:** generates role A, derives the shared key from the invitation challenge, and appends the role-A message plus explicit requester confirmation.
3. **Owner admission:** derives the same key, verifies requester confirmation, and appends the owner-signed membership epoch with admission confirmation.

The requester verifies admission confirmation automatically the next time it opens the vault. That local verification does not append another protocol message.

## Resumable owner state

The `spake2` crate does not serialize its state object. It does expose `start_b_with_rng`, so `git-vault` stores:

- a fresh 256-bit ChaCha20 RNG seed;
- the random invitation phrase.

Both are authenticated-encrypted under the current membership epoch key. Reconstructing role B with the same seed must reproduce the exact public invitation challenge before a join proof is accepted. The phrase and seed are never public Git fields.

Membership rotation invalidates all invitations and their encrypted owner state.

## Binding and confirmation

SPAKE2 identity strings bind the vault ID, invitation ID, and trusted parent hash.

Requester HMAC confirmation additionally binds:

- trusted invitation event hash;
- complete proposed Ed25519/X25519 identity;
- both SPAKE2 messages.

The owner admission HMAC binds:

- vault ID;
- parent trusted-state hash;
- exact accepted proposal hash;
- complete new membership epoch, excluding the confirmation field itself.

The join proposal is also signed by its proposed Ed25519 key. It remains inert until an existing owner verifies the PAKE confirmation and signs the membership epoch.

## Guessing properties

A passive repository reader sees both SPAKE2 group messages and confirmation tags but cannot test phrase guesses offline under SPAKE2's security model.

A malicious repository writer may submit arbitrary join attempts. Each attempt that an owner actively verifies permits one online phrase guess. Owners therefore choose which proposal to verify, invitations expire, membership changes invalidate invitations, and event/proposal limits bound log growth.

## Tests

The implementation tests:

- matching phrase shared-key agreement;
- wrong-phrase confirmation failure;
- invitation/context substitution resistance;
- proposal inertia before owner admission;
- admission of the exact proposal identity;
- requester verification of exact admission confirmation;
- local requester session-state Git refs.
