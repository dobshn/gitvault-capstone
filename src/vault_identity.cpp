#include "vault_identity.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "crypto/ctr.h"
#include "crypto/hmac.h"
#include "util.h"

namespace {
constexpr std::array<uint8_t, 4> kMagic = {'G', 'V', 'I', 'D'};
constexpr uint8_t kIdentityVersion = 1;
constexpr size_t kIvSize = 16;
constexpr size_t kSecretSize = 32;
constexpr size_t kTagSize = 32;
constexpr size_t kAuthenticatedSize = kMagic.size() + 1 + kIvSize + kSecretSize;
constexpr size_t kWrappedSize = kAuthenticatedSize + kTagSize;

// secp256k1 group order, encoded big-endian. Nostr signing keys must be in [1, n-1].
constexpr std::array<uint8_t, 32> kSecp256k1Order = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

void require_wrapping_keys(const Keys& keys) {
  if (keys.wrap_enc_key.size() != 32 || keys.wrap_mac_key.size() != 32) {
    throw std::runtime_error("invalid vault identity wrapping keys");
  }
}
}  // namespace

bool is_valid_vault_signing_secret(const std::array<uint8_t, 32>& secret) {
  const bool nonzero = std::any_of(secret.begin(), secret.end(),
                                   [](uint8_t byte) { return byte != 0; });
  return nonzero && std::lexicographical_compare(secret.begin(), secret.end(),
                                                 kSecp256k1Order.begin(),
                                                 kSecp256k1Order.end());
}

VaultIdentity generate_vault_identity() {
  VaultIdentity identity;
  do {
    ByteVec secret = random_bytes(identity.signing_secret.size());
    std::copy(secret.begin(), secret.end(), identity.signing_secret.begin());
  } while (!is_valid_vault_signing_secret(identity.signing_secret));
  return identity;
}

ByteVec wrap_vault_identity(const VaultIdentity& identity, const Keys& keys) {
  require_wrapping_keys(keys);
  if (identity.version != kIdentityVersion) {
    throw std::runtime_error("unsupported vault identity version");
  }
  if (!is_valid_vault_signing_secret(identity.signing_secret)) {
    throw std::runtime_error("invalid vault signing secret");
  }

  ByteVec iv = random_bytes(kIvSize);
  ByteVec plaintext(identity.signing_secret.begin(), identity.signing_secret.end());
  ByteVec ciphertext = aes256_ctr_crypt(keys.wrap_enc_key, iv, plaintext);

  ByteVec wrapped;
  wrapped.reserve(kWrappedSize);
  append_bytes(wrapped, kMagic.data(), kMagic.size());
  write_u8(wrapped, identity.version);
  append_bytes(wrapped, iv.data(), iv.size());
  append_bytes(wrapped, ciphertext.data(), ciphertext.size());

  const auto tag = hmac_sha256(keys.wrap_mac_key, wrapped);
  append_bytes(wrapped, tag.data(), tag.size());
  return wrapped;
}

VaultIdentity unwrap_vault_identity(const ByteVec& wrapped, const Keys& keys) {
  require_wrapping_keys(keys);
  if (wrapped.size() != kWrappedSize) {
    throw std::runtime_error("invalid wrapped vault identity size");
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), wrapped.begin())) {
    throw std::runtime_error("invalid wrapped vault identity magic");
  }
  if (wrapped[kMagic.size()] != kIdentityVersion) {
    throw std::runtime_error("unsupported vault identity version");
  }

  ByteVec authenticated(wrapped.begin(), wrapped.begin() + kAuthenticatedSize);
  ByteVec actual_tag(wrapped.begin() + kAuthenticatedSize, wrapped.end());
  const auto expected_tag_array = hmac_sha256(keys.wrap_mac_key, authenticated);
  ByteVec expected_tag(expected_tag_array.begin(), expected_tag_array.end());
  if (!constant_time_equal(actual_tag, expected_tag)) {
    throw std::runtime_error("vault identity authentication failed");
  }

  const size_t iv_offset = kMagic.size() + 1;
  const size_t ciphertext_offset = iv_offset + kIvSize;
  ByteVec iv(wrapped.begin() + iv_offset, wrapped.begin() + ciphertext_offset);
  ByteVec ciphertext(wrapped.begin() + ciphertext_offset,
                     wrapped.begin() + kAuthenticatedSize);
  ByteVec plaintext = aes256_ctr_crypt(keys.wrap_enc_key, iv, ciphertext);

  VaultIdentity identity;
  identity.version = kIdentityVersion;
  std::copy(plaintext.begin(), plaintext.end(), identity.signing_secret.begin());
  if (!is_valid_vault_signing_secret(identity.signing_secret)) {
    throw std::runtime_error("invalid vault signing secret");
  }
  return identity;
}

void save_wrapped_vault_identity_file(const std::filesystem::path& path,
                                      const ByteVec& wrapped_identity) {
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("vault identity already exists: " + path.string());
  }

  const std::filesystem::path trust_dir = path.parent_path();
  std::error_code ec;
  std::filesystem::create_directories(trust_dir, ec);
  if (ec) {
    throw std::runtime_error("failed to create trust metadata directory: " + ec.message());
  }
  std::filesystem::permissions(
      trust_dir,
      std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace,
      ec);
  if (ec) {
    throw std::runtime_error("failed to protect trust metadata directory: " + ec.message());
  }

  std::filesystem::path temp_path = path;
  temp_path += ".tmp-" + to_hex(random_bytes(8));
  try {
    std::ofstream file(temp_path, std::ios::binary | std::ios::trunc);
    if (!file) {
      throw std::runtime_error("failed to create temporary vault identity file");
    }

    std::filesystem::permissions(
        temp_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec);
    if (ec) {
      throw std::runtime_error("failed to protect temporary vault identity file: " + ec.message());
    }

    if (!wrapped_identity.empty()) {
      file.write(reinterpret_cast<const char*>(wrapped_identity.data()),
                 static_cast<std::streamsize>(wrapped_identity.size()));
    }
    file.close();
    if (!file) {
      throw std::runtime_error("failed to write temporary vault identity file");
    }

    std::filesystem::rename(temp_path, path, ec);
    if (ec) {
      throw std::runtime_error("failed to install vault identity file: " + ec.message());
    }
  } catch (...) {
    std::error_code cleanup_ec;
    std::filesystem::remove(temp_path, cleanup_ec);
    throw;
  }
}

ByteVec load_wrapped_vault_identity_file(const std::filesystem::path& path) {
  if (!std::filesystem::exists(path)) {
    throw std::runtime_error("vault identity not found: " + path.string());
  }
  return read_file_bytes(path);
}
