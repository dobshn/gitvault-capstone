# GitVault (C++)

A minimal C++ implementation of the GitVault design: encrypts files into Git-like objects (blob/tree/commit) and stores them in a flat object store. The store is untrusted; integrity is checked by object hashes. Objects are encrypted with AES-256-CTR (OpenSSL) and hashed with SHA-256, and large blobs are streamed to keep memory usage low.

## Build

Requires:
- OpenSSL (`libssl` + `libcrypto`)
- bundled headers in `src/`:
  - `httplib.h`
  - `json.hpp`

On macOS you may need `brew install openssl@3` and set `OPENSSL_ROOT_DIR`.

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
```

The refresh token file is created by `login`.
GitVault compares the local and cloud `HEAD` files before using the local trust anchor. A missing or mismatched local `HEAD` must be resolved explicitly with `sync`.

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
