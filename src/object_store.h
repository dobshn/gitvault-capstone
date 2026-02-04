#pragma once

#include <array>
#include <cstdint>
#include <filesystem>

#include "util.h"

struct Config {
  uint8_t version = 1;
  ByteVec salt;
  uint32_t iterations = 100000;
};

class ObjectStore {
 public:
  explicit ObjectStore(std::filesystem::path root);

  const std::filesystem::path& root() const;

  std::filesystem::path config_path() const;
  std::filesystem::path head_path() const;
  std::filesystem::path objects_dir() const;

  bool config_exists() const;
  Config load_config() const;
  void save_config(const Config& config) const;

  std::filesystem::path object_path(const std::array<uint8_t, 32>& hash) const;
  bool object_exists(const std::array<uint8_t, 32>& hash) const;
  void write_object(const std::array<uint8_t, 32>& hash, const ByteVec& data) const;
  ByteVec read_object(const std::array<uint8_t, 32>& hash) const;

 private:
  std::filesystem::path root_;
};
