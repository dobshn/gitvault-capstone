#include "object_store.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

ObjectStore::ObjectStore(std::filesystem::path root) : root_(std::move(root)) {}

const std::filesystem::path& ObjectStore::root() const {
  return root_;
}

std::filesystem::path ObjectStore::config_path() const {
  return root_ / "config";
}

std::filesystem::path ObjectStore::head_path() const {
  return root_ / "HEAD";
}

std::filesystem::path ObjectStore::objects_dir() const {
  return root_ / "objects";
}

bool ObjectStore::config_exists() const {
  return std::filesystem::exists(config_path());
}

Config ObjectStore::load_config() const {
  std::ifstream file(config_path());
  if (!file) {
    throw std::runtime_error("config not found: " + config_path().string());
  }

  Config cfg;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty()) {
      continue;
    }
    auto pos = line.find('=');
    if (pos == std::string::npos) {
      continue;
    }
    std::string key = line.substr(0, pos);
    std::string value = line.substr(pos + 1);
    if (key == "version") {
      cfg.version = static_cast<uint8_t>(std::stoul(value));
    } else if (key == "kdf_salt") {
      cfg.salt = from_hex(value);
    } else if (key == "kdf_iter") {
      cfg.iterations = static_cast<uint32_t>(std::stoul(value));
    }
  }

  if (cfg.version != 1) {
    throw std::runtime_error("unsupported config version");
  }
  if (cfg.salt.empty()) {
    throw std::runtime_error("config missing kdf_salt");
  }
  if (cfg.iterations == 0) {
    throw std::runtime_error("config missing kdf_iter");
  }
  return cfg;
}

void ObjectStore::save_config(const Config& config) const {
  std::filesystem::create_directories(root_);
  std::filesystem::create_directories(objects_dir());

  std::ofstream file(config_path(), std::ios::trunc);
  if (!file) {
    throw std::runtime_error("failed to write config: " + config_path().string());
  }
  file << "version=1\n";
  file << "kdf=pbkdf2-hmac-sha256\n";
  file << "kdf_iter=" << config.iterations << "\n";
  file << "kdf_salt=" << to_hex(config.salt) << "\n";
  file << "enc=aes-256-ctr\n";
}

std::filesystem::path ObjectStore::object_path(const std::array<uint8_t, 32>& hash) const {
  std::string hex = to_hex(hash);
  if (hex.size() != 64) {
    throw std::runtime_error("invalid hash length");
  }
  std::string dir = hex.substr(0, 2);
  std::string name = hex.substr(2);
  return objects_dir() / dir / name;
}

bool ObjectStore::object_exists(const std::array<uint8_t, 32>& hash) const {
  return std::filesystem::exists(object_path(hash));
}

void ObjectStore::write_object(const std::array<uint8_t, 32>& hash, const ByteVec& data) const {
  std::filesystem::path path = object_path(hash);
  if (std::filesystem::exists(path)) {
    return;
  }
  std::filesystem::create_directories(path.parent_path());
  write_file_bytes(path, data);
}

ByteVec ObjectStore::read_object(const std::array<uint8_t, 32>& hash) const {
  std::filesystem::path path = object_path(hash);
  if (!std::filesystem::exists(path)) {
    throw std::runtime_error("object not found: " + path.string());
  }
  return read_file_bytes(path);
}
