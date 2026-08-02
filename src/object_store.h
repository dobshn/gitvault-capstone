#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "API.h"
#include "dropbox_storage.h"
#include "util.h"

struct Config {
  uint8_t version = 2;
  ByteVec salt;
  uint32_t iterations = 100000;
};

class ObjectStore {
private:
  std::filesystem::path metadata_dir() const;
  std::filesystem::path config_path() const;
  std::filesystem::path head_path() const;
  std::filesystem::path vault_identity_path() const;

  std::string root_;
  std::optional<std::filesystem::path> local_metadata_root_;
  std::unique_ptr<API> CloudAPI;

public:
  ObjectStore();
  explicit ObjectStore(std::unique_ptr<API> cloud_api);
  ObjectStore(std::unique_ptr<API> cloud_api,
              std::filesystem::path local_metadata_root);
  ~ObjectStore() = default;
  void init(std::string access_token, std::string root_path);
  void fetch(std::string access_token, std::string root_path);
  bool destroy(std::string access_token, std::string root_path);

  const std::string& root() const;
  std::filesystem::path trust_directory() const;
  std::filesystem::path local_metadata_directory() const;
  bool remove_local_metadata() const;

  bool config_exists() const;
  Config load_config() const;
  void save_config(const Config& config) const;
  ByteVec read_local_config_bytes() const;
  ByteVec read_cloud_config_bytes() const;
  void write_local_config_bytes(const ByteVec& bytes) const;

  void install_initial_head(const ByteVec& data) const;
  ByteVec read_head() const;
  ByteVec read_local_head() const;
  void write_local_head(const ByteVec& data) const;
  VersionedBytes read_cloud_head_versioned() const;
  ConditionalWriteResult compare_exchange_cloud_head(
      const ByteVec& data,
      std::string_view expected_revision) const;
  ConditionalWriteResult create_cloud_head(const ByteVec& data) const;

  bool vault_identity_exists() const;
  void save_vault_identity(const ByteVec& wrapped_identity) const;
  ByteVec load_vault_identity() const;

  std::string object_key(const std::array<uint8_t, 32>& hash) const;
  bool object_exists(const std::array<uint8_t, 32>& hash) const;
  bool remove_object(const std::array<uint8_t, 32>& hash) const;
  void write_object(const std::array<uint8_t, 32>& hash, const ByteVec& data) const;
  void write_object_from_file(const std::array<uint8_t, 32>& hash, const std::filesystem::path& path) const;
  ByteVec read_object(const std::array<uint8_t, 32>& hash) const;

};
