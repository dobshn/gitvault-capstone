# GitVault (C++)

A minimal C++ implementation of the GitVault design: encrypts files into Git-like objects (blob/tree/commit) and stores them in a flat object store. The store is untrusted; integrity is checked by object hashes. Objects are encrypted with AES-256-CTR (OpenSSL) and hashed with SHA-256, and large blobs are streamed to keep memory usage low.

## Build

Requires:
- OpenSSL (`libssl` + `libcrypto`)
- libsecp256k1 with extrakeys and Schnorr signature modules
- bundled headers in `src/`:
  - `httplib.h`
  - `json.hpp`

On macOS you may need `brew install openssl@3 secp256k1` and set `OPENSSL_ROOT_DIR`.

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

# Initialize a vault in Dropbox and optionally upload a local folder
./build/gitvault init <vault_name> [folder_path]

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
```

The refresh token file is created by `login`.
GitVault compares the local and cloud `HEAD` files before using the local trust anchor. A missing or mismatched local `HEAD` must be resolved explicitly with `sync`.
Config V2 derives one 32-byte master key with PBKDF2, then uses HKDF-SHA256 labels to derive separate object-encryption, HEAD-MAC, identity-wrapping-encryption, and identity-wrapping-MAC keys.
New vaults also generate one random secp256k1-compatible signing secret. It is encrypted and authenticated with the identity wrapping keys before being stored locally as `vault-identity.enc`; GitVault does not intentionally write the plaintext signing secret to a file.
Password-authenticated commands reject a vault whose local identity is missing. Config V1 and vaults created before this identity format must currently be reinitialized; key-schedule migration and cross-device import are not implemented yet.

### Signed anchor events

GitVault has a channel-independent NIP-01 event envelope for future anchor-channel messages. It derives the Vault's x-only public key from the wrapped signing secret, serializes unsigned event fields exactly as `[0, pubkey, created_at, kind, tags, content]`, hashes those UTF-8 JSON bytes with SHA-256 for the event ID, and signs the ID with BIP-340 Schnorr.

On input, the parser requires exactly the seven unique NIP-01 wire fields and fixed-length lowercase hexadecimal encodings. Verification first requires the event public key to match the trusted Vault public key, then recomputes the canonical event ID before verifying the signature. Thus an unrelated self-signed event and any change to the content, tags, metadata, ID, public key, or signature are rejected.

This layer does not yet publish events or interpret `content` as a Proposal/Observation. Payload encryption, channel synchronization, and fork-state transitions belong to the following implementation stages.

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
./build/gitvault init "$VAULT_NAME" "$WORK/plain" --password test123
./build/gitvault list "$VAULT_NAME" --password test123
./build/gitvault tree "$VAULT_NAME" --password test123
./build/gitvault cat "$VAULT_NAME" a.txt --password test123
./build/gitvault quick-scan "$VAULT_NAME" --password test123
./build/gitvault deep-scan "$VAULT_NAME" --password test123
```
