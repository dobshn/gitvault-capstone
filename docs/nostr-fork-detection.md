# Vector-clock/CAS fork detection

GitVault treats Dropbox as the object and mutable-HEAD data plane. Nostr is a witness that retains the latest encrypted, signed checkpoint for each replica; it is not a consensus service.

## Identifiers and clocks

Each initialized or imported client generates a random 128-bit `replica_id`. All replicas still share the Vault signing key and are one trust principal. The ID selects one vector-clock component and one Nostr address; it is not a device public key and provides no cryptographic attribution or revocation.

Zero components are omitted. A new replica first appears when its first Dropbox CAS succeeds. An inactive replica's component remains frozen. Reinstallations receive a new ID instead of reusing a possibly stale counter.

For clocks `a` and `b`:

- `a < b` when every component of `a` is no greater and at least one is smaller.
- `a || b` when neither clock is no greater than the other.
- Missing components are zero.
- Equal clocks that authenticate different HEAD states are equivocation.

The implementation caps clocks at 256 components and fails closed. It does not automatically delete components or compact epochs.

## Authenticated HEAD V2

The Dropbox `HEAD` envelope encrypts and HMAC-authenticates:

```text
VaultHeadState {
  format_version = 2
  protocol_epoch
  head_commit
  vector_clock
  writer_replica_id
  operation_id
}
```

The vector clock and Commit hash are one authenticated unit. Dropbox can replay or split valid envelopes but cannot create a new one without the Vault keys.

## Latest signed checkpoints

Checkpoints are NIP-44 encrypted Nostr addressable events:

```text
kind = 30078
tags = [
  ["t", channel_id],
  ["d", "gitvault:<vault-id>:<replica-id>"]
]
```

Their signed payload contains the HEAD, vector clock, operation ID, SHA-256 of the exact encrypted HEAD envelope, and the Dropbox revision observed after CAS. NIP-01 permits relays to retain only the latest event for each `(kind, pubkey, d)` address, bounding live witness state by the number of replicas rather than the number of writes.

`created_at` is made monotonically increasing for replacement behavior, but has no security ordering meaning. Vector clocks determine ordering.

## Durable write boundary

```text
R=2 fetch and vector validation
  -> acquire local process lock
  -> prepare immutable objects and Commit(parent=current HEAD)
  -> increment this replica's vector component
  -> persist exact encrypted candidate HEAD in prepared.json
  -> Dropbox HEAD CAS(expected revision)
  -> exact HEAD bytes and returned/readback revision comparison
  -> persist signed checkpoint in outbox
  -> checkpoint W=2
  -> local HEAD and authenticated checkpoint
  -> clear journal/outbox
```

A CAS conflict creates no signed checkpoint. Objects prepared before the conflict remain append-only. A crash after CAS is recovered from the exact candidate bytes and checkpoint outbox.

## Decisions

- `cloud < local trusted`: `ROLLBACK_DETECTED`.
- `cloud || local` or any two signed checkpoints are concurrent: `FORKED`.
- Equal clocks with different HEAD/envelope/operation: `FORKED`.
- `local < cloud = signed checkpoint`: verify Commit ancestry and catch up.
- `latest witness < cloud`: verify ancestry, publish a recovery checkpoint, then adopt.
- `R < 2`: block writes; allow only a local/cloud-equal degraded read.

On honest Dropbox, two clients based on one revision may create concurrent candidates, but revision CAS allows only one to be committed and the loser signs nothing. If Dropbox confirms both split views, the clients publish incompatible checkpoints at their separate replica addresses. Once both are delivered to a client, vector comparison detects the fork.

This is evidence of inconsistent CAS-visible state, not attribution of intent. A compromised client holding the shared Vault key can fabricate checkpoints and is a full Vault compromise under the current threat model.

## Space bound

Nostr and local checkpoint metadata are `O(number of replica IDs)` and constant in operation count. Dropbox Commit/Tree/Blob storage remains append-only and therefore is not constant. Device-key membership, secure device revocation, vector-component compaction, and object garbage collection are separate protocols and are not implemented.

## Tests

```bash
cmake -S . -B build
cmake --build build -j4

# Pure vector-clock ordering, zero-component, overflow, and 256-replica limit
./build/gitvault_vector_clock_tests

# Two replicas, CAS conflict, frozen component, W=1 recovery, degraded read,
# and malicious-CAS incompatible checkpoint detection
./build/gitvault_anchor_coordinator_integration_tests

# Entire suite
ctest --test-dir build --output-on-failure
```
