#pragma once

#include <array>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>

#include "format.h"
#include "object_store.h"

struct Keys {
  ByteVec enc_key;
  ByteVec mac_key;
};

struct ScanStats {
  size_t trees_checked = 0;
  size_t blobs_checked = 0;
  size_t blobs_missing = 0;
  size_t blobs_hashed = 0;
};

Config ensure_store_config(ObjectStore& store);
Keys derive_keys(const Config& config, const std::string& password);

std::array<uint8_t, 32> lock_vault(const std::filesystem::path& plain_dir,
                                  ObjectStore& store,
                                  const Keys& keys,
                                  const std::filesystem::path& state_path);

Tree list_directory(const ObjectStore& store,
                    const Keys& keys,
                    const std::optional<std::filesystem::path>& state_path,
                    const std::string& path);

Entry resolve_entry(const ObjectStore& store,
                    const Keys& keys,
                    const std::optional<std::filesystem::path>& state_path,
                    const std::string& path,
                    bool require_directory);

ByteVec read_file_from_vault(const ObjectStore& store,
                             const Keys& keys,
                             const std::optional<std::filesystem::path>& state_path,
                             const std::string& path);

ScanStats quick_scan(const ObjectStore& store,
                     const Keys& keys,
                     const std::optional<std::filesystem::path>& state_path);

ScanStats deep_scan(const ObjectStore& store,
                    const Keys& keys,
                    const std::optional<std::filesystem::path>& state_path);

void print_tree(const ObjectStore& store,
                const Keys& keys,
                const std::optional<std::filesystem::path>& state_path,
                const std::string& path,
                std::ostream& out);
