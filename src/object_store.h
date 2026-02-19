#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

#include "dropbox_storage.h"
#include "util.h"

struct Config {
  uint8_t version = 1;
  ByteVec salt;
  uint32_t iterations = 100000;
};

class ObjectStore {
 public:
  ObjectStore(std::string access_token, std::string root_path);

  const std::string& root() const;

  bool config_exists() const;
  Config load_config() const;
  void save_config(const Config& config) const;

  void write_head(const ByteVec& data) const;
  ByteVec read_head() const;

  std::string object_key(const std::array<uint8_t, 32>& hash) const;
  bool object_exists(const std::array<uint8_t, 32>& hash) const;
  bool remove_object(const std::array<uint8_t, 32>& hash) const;
  void write_object(const std::array<uint8_t, 32>& hash, const ByteVec& data) const;
  void write_object_from_file(const std::array<uint8_t, 32>& hash, const std::filesystem::path& path) const;
  ByteVec read_object(const std::array<uint8_t, 32>& hash) const;

 private:
  std::filesystem::path config_path() const;

  std::string root_;
  DropboxStorage storage_;
};
