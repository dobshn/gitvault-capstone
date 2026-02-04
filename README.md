# GitVault (C++)

A minimal C++ implementation of the GitVault design: encrypts files into Git-like objects (blob/tree/commit) and stores them in a flat object store. The store is untrusted; integrity is checked by object hashes. Objects are encrypted with AES-256-CTR (OpenSSL) and hashed with SHA-256, and large blobs are streamed to keep memory usage low.

## Build

Requires OpenSSL (libcrypto). On macOS you may need `brew install openssl` and set `OPENSSL_ROOT_DIR`.

```
cmake -S . -B build
cmake --build build
```

## Usage

```
# Initialize an empty object store (creates config)
./build/gitvault init <store_dir>

# Encrypt a plaintext directory into the store
./build/gitvault lock <plain_dir> <store_dir>

# List a directory inside the vault (lazy load)
./build/gitvault list <store_dir> [path]

# Print the directory structure as a tree
./build/gitvault tree <store_dir> [path]

# Print a file from the vault
./build/gitvault cat <store_dir> <path>

# Quick scan: verify commit/tree links and blob existence
./build/gitvault quick-scan <store_dir>

# Deep scan: verify commit/tree and re-hash all blobs
./build/gitvault deep-scan <store_dir>
```

### Password input

Provide the password via one of:

```
--password <text>
--password-file <path>
```

If not provided, the tool prompts on stdin.

### Local state

`lock` writes a trusted local state file at:

```
<plain_dir>/.gitvault_state
```

This file stores the latest commit hash. Commands that need a commit hash will use this file if provided via `--state <path>`. If `--state` is not supplied, the tool uses the encrypted `HEAD` file stored in the object store.

### Store layout

```
<store_dir>/
  config
  HEAD
  objects/
    ab/
      cdef...  (SHA-256 hash split by first byte)
```

The `HEAD` file contains the encrypted commit hash plus an HMAC for integrity.
