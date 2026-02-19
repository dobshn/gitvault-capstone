# GitVault (C++)

A minimal C++ implementation of the GitVault design: encrypts files into Git-like objects (blob/tree/commit) and stores them in a flat object store. The store is untrusted; integrity is checked by object hashes. Objects are encrypted with AES-256-CTR (OpenSSL) and hashed with SHA-256, and large blobs are streamed to keep memory usage low.

## Build

Requires:
- OpenSSL (`libssl` + `libcrypto`)
- bundled headers in `src/`:
  - `httplib.h`
  - `json.hpp`

On macOS you may need `brew install openssl` and set `OPENSSL_ROOT_DIR`.

```
cmake -S . -B build
cmake --build build
```

## Usage

```
# Initialize an empty object store in Dropbox (creates config)
./build/gitvault init /my_gitvault --dropbox-token <token>

# Encrypt a plaintext directory into Dropbox
./build/gitvault lock <plain_dir> /my_gitvault --dropbox-token <token>

# Add one local file into an existing vault path
./build/gitvault add /my_gitvault <local_path> <cloud_path> --dropbox-token <token>

# Remove one file from an existing vault path
./build/gitvault remove /my_gitvault <cloud_path> --dropbox-token <token>

# List a directory inside the vault (lazy load)
./build/gitvault list /my_gitvault [path] --dropbox-token <token>

# Print the directory structure as a tree
./build/gitvault tree /my_gitvault [path] --dropbox-token <token>

# Print a file from the vault
./build/gitvault cat /my_gitvault <path> --dropbox-token <token>

# Quick scan: verify commit/tree links and blob existence
./build/gitvault quick-scan /my_gitvault --dropbox-token <token>

# Deep scan: verify commit/tree and re-hash all blobs
./build/gitvault deep-scan /my_gitvault --dropbox-token <token>
```

### Password input

Provide secrets via:

```
--dropbox-token <token>
--password <text>
--password-file <path>
```

If `--dropbox-token` is omitted, the tool uses `GITVAULT_DROPBOX_TOKEN` or `DROPBOX_ACCESS_TOKEN`.
If password is not provided, the tool prompts on stdin.

### Local metadata

Vault metadata is stored locally at:

```
~/.gitvault/<vault_name>/
  config
  HEAD
```

`HEAD` is read from local storage first. If the local `HEAD` file is missing, GitVault falls back to the cloud `HEAD` and prints a warning.

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

# 2) 토큰/테스트 데이터 준비
export GITVAULT_DROPBOX_TOKEN="<YOUR_DROPBOX_TOKEN>"
ROOT="/gitvault-smoke-$(date +%s)"
WORK="$(mktemp -d)"
mkdir -p "$WORK/plain/sub"
echo "hello vault" > "$WORK/plain/a.txt"
echo '{"ok":true}' > "$WORK/plain/sub/b.json"

# 3) Dropbox vault 동작 확인
./build/gitvault init "$ROOT"
./build/gitvault lock "$WORK/plain" "$ROOT" --password test123
./build/gitvault list "$ROOT" --password test123
./build/gitvault tree "$ROOT" --password test123
./build/gitvault cat "$ROOT" a.txt --password test123
./build/gitvault quick-scan "$ROOT" --password test123
./build/gitvault deep-scan "$ROOT" --password test123
```
