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
# Initialize an empty object store in Dropbox
./build/gitvault init <vault_name> --dropbox-token <token>

# Encrypt a plaintext directory into Dropbox
./build/gitvault lock <plain_dir> <vault_name> --dropbox-token <token>

# Add one local file into a vault path (missing parent directories are created automatically)
./build/gitvault add <vault_name> <local_path> <cloud_path> --dropbox-token <token>

# Remove one file from an existing vault path
./build/gitvault remove <vault_name> <cloud_path> --dropbox-token <token>

# Create one directory in a vault path (missing parent directories are created automatically)
./build/gitvault mkdir <vault_name> <cloud_dir_path> --dropbox-token <token>

# Remove one directory from an existing vault path (non-empty requires confirm)
./build/gitvault rmdir <vault_name> <cloud_dir_path> --dropbox-token <token>

# List a directory inside the vault (lazy load)
./build/gitvault list <vault_name> [path] --dropbox-token <token>

# Print the directory structure as a tree
./build/gitvault tree <vault_name> [path] --dropbox-token <token>

# Print a file from the vault
./build/gitvault cat <vault_name> <path> --dropbox-token <token>

# Quick scan: verify commit/tree links and blob existence
./build/gitvault quick-scan <vault_name> --dropbox-token <token>

# Deep scan: verify commit/tree and re-hash all blobs
./build/gitvault deep-scan <vault_name> --dropbox-token <token>
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
`vault_name` can be `my_vault` or `/my_vault`.

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
VAULT_NAME="gitvault-smoke-$(date +%s)"
WORK="$(mktemp -d)"
mkdir -p "$WORK/plain/sub"
echo "hello vault" > "$WORK/plain/a.txt"
echo '{"ok":true}' > "$WORK/plain/sub/b.json"

# 3) Dropbox vault 동작 확인
./build/gitvault init "$VAULT_NAME"
./build/gitvault lock "$WORK/plain" "$VAULT_NAME" --password test123
./build/gitvault list "$VAULT_NAME" --password test123
./build/gitvault tree "$VAULT_NAME" --password test123
./build/gitvault cat "$VAULT_NAME" a.txt --password test123
./build/gitvault quick-scan "$VAULT_NAME" --password test123
./build/gitvault deep-scan "$VAULT_NAME" --password test123
```
