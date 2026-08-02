# Nostr-based fork detection implementation

GitVault treats Dropbox as the object/HEAD data plane and signed, NIP-44-encrypted Nostr events as externally replicated evidence. It does not treat relay quorum as consensus.

## Decision inputs

- `L`: HEAD in the authenticated local checkpoint.
- `C`: HEAD decrypted from the current Dropbox file revision.
- `N`: unique tip of the verified Genesis/Proposal/Observation graph.
- `W`: a locally journaled prepared transition that is not fully checkpointed.

All ordering is Commit V2 parent ancestry. Nostr `created_at` and arrival order are diagnostics only.

The important outcomes are:

- `L<C=N`: verify ancestry, install the exact cloud HEAD bytes locally, and advance the checkpoint.
- `C<N` on the observed lineage: report `ROLLBACK_DETECTED`.
- `N<C`: require an exact Proposal whose Commit parent is valid, then publish the missing Observation and reevaluate.
- parallel `C` explained by a Proposal: observe it; two resulting observed branches report `FORKED`.
- relay `EOSE` count below two: block writes; permit only a freshness-degraded read when `L=C=checkpoint`.

## Durable write boundary

Objects are installed with create-if-absent and are never removed by a mutation. The only mutable remote file is HEAD, and its update requires the Dropbox revision read by preflight.

```text
R=2 fetch and validate
  -> persist prepared.json
  -> persist/sign Proposal in outbox
  -> Proposal W=2
  -> Dropbox HEAD CAS(expected revision)
  -> read back HEAD and revision
  -> persist/sign Observation in outbox
  -> Observation W=2
  -> exact cloud HEAD + authenticated checkpoint
  -> clear completed journal/outbox
```

Restart repeats idempotent event publication and resumes from the recorded phase. A CAS conflict creates no Observation, never rebases automatically, and preserves prepared immutable objects and signed Proposal evidence.

## Relay protocol and leakage

The production adapter uses `wss://` (plain `ws://` is accepted only for loopback tests), kind `9500`, author, and a single random `t` tag. It waits for the matching publish `OK` and fetch `EOSE`, supports NIP-42 challenges, and stops rather than truncating oversized histories. Semantic content and HEADs are NIP-44 encrypted, but relay operators still see the public key, event time, size, channel tag, selected relays, IP-layer metadata, and activity frequency.

## Bootstrap trust

`export-client` is allowed only after an `R=2` synchronization in `CONSISTENT`. The canonical bootstrap contains the exact Vault config, password-wrapped Vault identity, channel/Genesis pin, accepted checkpoint, and verified event cache. It contains no Dropbox token or plaintext password. `import-client` verifies the password-wrapped identity, exact Dropbox config, bootstrap evidence, current relay union, and current Dropbox HEAD before keeping local metadata. The transfer channel itself is assumed confidential and integrity protected.

## Evaluation

Automated tests cover official NIP-44 vectors, event/signature tampering, relay `OK`/`EOSE`/AUTH/replay/same-ID conflicts, state relation matrices, rollback versus fork, W/R failures, authenticated journal tampering, two independent client roots, revision CAS conflict, and append-only object retention.

For experiments, compare LocalFile, one relay, and `N=3/W=2/R=2` with the same history and payload. Record init/read/write p50/p95, event bytes, relay round trips, verification time and peak RSS at 1/10/100/1,000 commits, one-relay outage behavior, crash recovery time, and time until independently observed split views meet. Full-history fetch is intentionally the baseline; optimize with a checkpoint event or NIP-77 only after measurements show it is the bottleneck.

The reproducible CPU/history baseline emits CSV:

```bash
./build/gitvault_anchor_history_benchmark
# or select sizes
./build/gitvault_anchor_history_benchmark 1 10 100 1000
```

2026-08-02 개발 환경의 한 reference run(7회, 생성 시간 제외)은 다음과 같았다. 이는 CPU/event-graph baseline이며 실제 relay·Dropbox 지연은 포함하지 않는다.

| commits | events | wire bytes | verify p50 | verify p95 |
|---:|---:|---:|---:|---:|
| 1 | 3 | 2,746 | 0.97 ms | 1.36 ms |
| 10 | 21 | 20,030 | 5.07 ms | 6.10 ms |
| 100 | 201 | 193,113 | 47.08 ms | 47.21 ms |
| 1,000 | 2,001 | 1,926,616 | 1,759.44 ms | 1,765.16 ms |

1,000 commit에서 증가 폭이 커지므로 현재 반복 reference resolver가 우선 최적화 후보임을 확인했다. 실제 LocalFile/Nostr N=1/N=3 종단 지연은 실험자가 선택한 relay와 Dropbox 계정에서 별도로 측정해야 한다.

## Explicit limits

One active writer is a user contract. A malicious replica that knows both the password and Vault signing secret is out of scope. Permanent Dropbox/relay censorship or permanent partitions cannot guarantee detection. `C=N` proves a verified common prefix, not global freshness. There is no merge Commit, offline write, GC, key rotation, per-device revocation, or Email adapter in this version.
