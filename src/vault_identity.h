#pragma once

#include <array>
#include <cstdint>
#include <filesystem>

#include "crypto/ICrypto.h"

struct VaultIdentity {
  uint8_t version = 1;
  std::array<uint8_t, 32> signing_secret{};
};

bool is_valid_vault_signing_secret(const std::array<uint8_t, 32>& secret);
VaultIdentity generate_vault_identity();
ByteVec wrap_vault_identity(const VaultIdentity& identity, const Keys& keys);
VaultIdentity unwrap_vault_identity(const ByteVec& wrapped, const Keys& keys);
void save_wrapped_vault_identity_file(const std::filesystem::path& path,
                                      const ByteVec& wrapped_identity);
ByteVec load_wrapped_vault_identity_file(const std::filesystem::path& path);
