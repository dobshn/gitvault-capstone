# GitVault (C++)

A minimal C++ implementation of the GitVault design: encrypts files into Git-like objects (blob/tree/commit) and stores them in a flat object store. The store is untrusted; integrity is checked by object hashes. Objects are encrypted with AES-256-CTR (OpenSSL) and hashed with SHA-256, and large blobs are streamed to keep memory usage low.

## Build

Requires:
- OpenSSL (`libssl` + `libcrypto`)
- libsecp256k1 with extrakeys and Schnorr signature modules
- Boost.Asio/Beast headers (WebSocket/TLS Nostr transport)
- bundled headers in `src/`:
  - `httplib.h`
  - `json.hpp`

On macOS you may need `brew install openssl@3 secp256k1 boost` and set `OPENSSL_ROOT_DIR`.

```
cmake -S . -B build
cmake --build build
```

## Usage

```
# Log in to Dropbox via browser-based OAuth and save a local refresh token
./build/gitvault login

# Remove the saved refresh token
./build/gitvault logout

# Initialize a vault and pin three user-selected Nostr relays
./build/gitvault init <vault_name> [folder_path] \
  --relay wss://relay-1.example \
  --relay wss://relay-2.example \
  --relay wss://relay-3.example

# Destroy a vault completely (local metadata + Dropbox folder)
./build/gitvault destroy <vault_name>

# Add one local file into a vault path (missing parent directories are created automatically)
./build/gitvault add <vault_name> <local_path> <cloud_path>

# Remove one file from an existing vault path
./build/gitvault remove <vault_name> <cloud_path>

# Create one directory in a vault path (missing parent directories are created automatically)
./build/gitvault mkdir <vault_name> <cloud_dir_path>

# Remove one directory from an existing vault path (non-empty requires confirm)
./build/gitvault rmdir <vault_name> <cloud_dir_path>

# List a directory inside the vault (lazy load)
./build/gitvault list <vault_name> [path]

# Print the directory structure as a tree
./build/gitvault tree <vault_name> [path]

# Print a file from the vault
./build/gitvault cat <vault_name> <path>

# Quick scan: verify commit history/tree links and blob existence
./build/gitvault quick-scan <vault_name>

# Deep scan: verify commit/tree and re-hash all blobs
./build/gitvault deep-scan <vault_name>

# Explain L/C/N, relay EOSE results, pending write and the decision
./build/gitvault status <vault_name>

# Verify relay/Dropbox state and perform only a safe catch-up/recovery
./build/gitvault sync <vault_name>

# Transfer an existing verified checkpoint to a new device
./build/gitvault export-client <vault_name> <bootstrap_file>
./build/gitvault import-client <bootstrap_file>
```

### Dropbox login

Run this once before using vault commands:

```bash
./build/gitvault login
```

`login` starts a local OAuth callback server on `127.0.0.1` using a free port in the `8080-8100` range, opens the Dropbox authorization URL in your browser when possible, and stores the Dropbox refresh token locally at `~/.gitvault/.gitvault_refresh_token`.

If the browser cannot be opened automatically, GitVault prints the URL so you can open it manually. To remove the saved refresh token later:

```bash
./build/gitvault logout
```

All other commands automatically exchange the saved refresh token for a short-lived Dropbox access token. If you are not logged in, commands will fail and ask you to run `login` first.

### Password input

Provide the vault password via:

```
--password <text>
```

If password is not provided, the tool prompts on stdin.
`vault_name` can be `my_vault` or `/my_vault`.

`destroy` removes both `~/.gitvault/<vault_name>/` and the Dropbox folder `/<vault_name>` after a confirmation prompt.

### Local metadata

GitVault stores local state at:

```
~/.gitvault/.gitvault_refresh_token
~/.gitvault/<vault_name>/
  config
  HEAD
  trust/
    vault-identity.enc
    channel.json
    checkpoint.json
    prepared.json             # only while a write is pending
    events/<event-id>.json
    outbox/<event-id>.json
```

The refresh token file is created by `login`.
`checkpoint.json` is the authenticated local trust anchor. GitVault compares its accepted local HEAD (`L`), Dropbox's revisioned HEAD (`C`), and the unique verified Observation tip (`N`) before every read or write. `sync` no longer copies Dropbox HEAD unconditionally.
Config V2 derives one 32-byte master key with PBKDF2, then uses HKDF-SHA256 labels to derive separate object-encryption, HEAD-MAC, identity-wrapping-encryption, and identity-wrapping-MAC keys.
New vaults also generate one random secp256k1-compatible signing secret. It is encrypted and authenticated with the identity wrapping keys before being stored locally as `vault-identity.enc`; GitVault does not intentionally write the plaintext signing secret to a file.
Password-authenticated commands reject a vault whose local identity is missing. Config V1 is unsupported. `export-client` includes exact config bytes, the wrapped Vault identity, a checkpoint, and signed evidence; it never includes a Dropbox token or plaintext password. The bootstrap file must be moved through a confidential, integrity-protected one-time channel such as a trusted USB transfer or AirDrop.

### Encrypted signed anchor events

GitVault uses a channel-independent NIP-01 event envelope for anchor messages. It derives the Vault's x-only public key from the wrapped signing secret, serializes unsigned event fields exactly as `[0, pubkey, created_at, kind, tags, content]`, hashes those UTF-8 JSON bytes with SHA-256 for the event ID, and signs the ID with BIP-340 Schnorr.

On input, the parser requires exactly the seven unique NIP-01 wire fields and fixed-length lowercase hexadecimal encodings. Verification first requires the event public key to match the trusted Vault public key, then recomputes the canonical event ID before verifying the signature. Thus an unrelated self-signed event and any change to the content, tags, metadata, ID, public key, or signature are rejected.

Public kind `9500` events contain exactly one searchable `t` tag holding a random 32-byte channel ID. Genesis, Proposal, Observation, Vault ID, operation ID, and HEAD values are canonical JSON encrypted with NIP-44 v2 self-encryption. GitVault verifies the outer public key, canonical event ID, Schnorr signature, kind, and channel tag before decrypting the content. Relays still learn the Vault public key, timestamps, event sizes, relay selection, and activity frequency.

### Anchor channel abstraction

`IAnchorChannel` separates immutable event transport from Vault security decisions. `publish()` reports `OK`, rejection, timeout, or transport failure per endpoint; `fetch()` reports `EOSE` or failure per endpoint and returns the event-ID union. A receipt or filter match does not make an event trusted.

`LocalFileAnchorChannel` is the deterministic test adapter. It stores one JSON file per event ID under `<channel-root>/events/<event-id>.json`. Publishing the same event again is idempotent, and an existing ID is never overwritten with different bytes. Concurrent publishers install the completed event with an atomic no-replace hard link. Fetch results are sorted by event ID only for reproducible tests; that order has no security meaning.

`NostrAnchorChannel` uses WebSocket/TLS, connects to all configured relays in parallel, counts only a matching `OK=true`, waits for `EOSE`, deduplicates exact event IDs, handles NIP-42 AUTH with the Vault key, and rejects same-ID/different-bytes responses. It performs no hidden retry: the authenticated outbox retries on the next command. The initial implementation fetches the full history and stops at 4,096 events or configured frame/content limits.

### Proposal/Observation state machine

GitVault has canonical semantic payloads for `VAULT_GENESIS`, `HEAD_PROPOSAL`, and `HEAD_OBSERVATION`. Genesis pins the exact config hash and initial Commit. A Proposal links a verified parent event and `previous_head -> new_head` Commit V2 transition. An Observation references one Proposal and records the cloud HEAD and Dropbox revision read back after CAS.

The state evaluator starts from pinned Genesis, ignores delivery order and `created_at`, validates Commit V2 parents, and compares `L`, `C`, and `N` by ancestry. It returns `CONSISTENT`, `LOCAL_CATCH_UP`, `WRITE_PREPARED`, `PROPOSED`, `OBSERVATION_REQUIRED`, `ANNOUNCED`, `DEGRADED_READ_ONLY`, `ROLLBACK_DETECTED`, `FORKED`, or `RECOVERY_REQUIRED`, with a separate reason and action.

Two competing Proposals alone are not a fork. Different observed children are a fork; `C<N` on one lineage is a separately reported rollback. `N<C` is accepted only when an exact valid Proposal explains `C`, after which any replica can publish the missing Observation. Missing references, a bad Commit parent, a parallel local checkpoint, and an unexplained cloud HEAD fail closed.

Writes are single-writer and online-only: prepare append-only objects, fsync the journal, publish Proposal to `W=2`, change Dropbox HEAD by expected revision, read it back, publish Observation to `W=2`, then advance local HEAD/checkpoint. Reads require `R=2`; if relay synchronization is incomplete, only `L=C=checkpoint` may be read with a freshness warning. Querying two of three relays improves availability but can miss fork evidence held only by the omitted relay. There is no merge, offline write, object GC, key rotation, device revocation, or consensus among relays.

### Remote store layout

```
<dropbox_root>/
  HEAD
  objects/
    <sha256-hex>
```

The `HEAD` file contains the encrypted commit hash plus an HMAC for integrity.

## Smoke Test

```bash
# 1) 빌드
cmake -S . -B build && cmake --build build -j4

# 2) Dropbox 로그인 (브라우저 인증 필요, 한 번만 하면 됨)
./build/gitvault login

# 3) 테스트 데이터 준비
VAULT_NAME="gitvault-smoke-$(date +%s)"
WORK="$(mktemp -d)"
mkdir -p "$WORK/plain/sub"
echo "hello vault" > "$WORK/plain/a.txt"
echo '{"ok":true}' > "$WORK/plain/sub/b.json"

# 4) Dropbox vault 동작 확인
./build/gitvault init "$VAULT_NAME" "$WORK/plain" --password test123 \
  --relay wss://relay-1.example \
  --relay wss://relay-2.example \
  --relay wss://relay-3.example
./build/gitvault status "$VAULT_NAME" --password test123
./build/gitvault list "$VAULT_NAME" --password test123
./build/gitvault tree "$VAULT_NAME" --password test123
./build/gitvault cat "$VAULT_NAME" a.txt --password test123
./build/gitvault quick-scan "$VAULT_NAME" --password test123
./build/gitvault deep-scan "$VAULT_NAME" --password test123
```
