#include "object_store.h"

#include <sstream>
#include <stdexcept>
#include <utility>

namespace {
constexpr const char* kConfigKey = "config";
constexpr const char* kHeadKey = "HEAD";
}

ObjectStore::ObjectStore(std::string access_token, std::string root_path)
    : root_(std::move(root_path)), storage_(std::move(access_token), root_) {
  storage_.init();
}

const std::string& ObjectStore::root() const {
  return root_;
}

bool ObjectStore::config_exists() const {
  return storage_.exists(kConfigKey);
}

Config ObjectStore::load_config() const {
  if (!config_exists()) {
    throw std::runtime_error("config not found: " + root_ + "/" + kConfigKey);
  }

  ByteVec data = storage_.get(kConfigKey);
  std::string text(data.begin(), data.end());
  std::istringstream file(text);

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
  std::ostringstream oss;
  oss << "version=1\n";
  oss << "kdf=pbkdf2-hmac-sha256\n";
  oss << "kdf_iter=" << config.iterations << "\n";
  oss << "kdf_salt=" << to_hex(config.salt) << "\n";
  oss << "enc=aes-256-ctr\n";

  std::string text = oss.str();
  ByteVec data(text.begin(), text.end());
  storage_.put(kConfigKey, data, true);
}

void ObjectStore::write_head(const ByteVec& data) const {
  storage_.put(kHeadKey, data, true);
}

ByteVec ObjectStore::read_head() const {
  return storage_.get(kHeadKey);
}

std::string ObjectStore::object_key(const std::array<uint8_t, 32>& hash) const {
  std::string hex = to_hex(hash);
  if (hex.size() != 64) {
    throw std::runtime_error("invalid hash length");
  }
  return "objects/" + hex;
}

bool ObjectStore::object_exists(const std::array<uint8_t, 32>& hash) const {
  return storage_.exists(object_key(hash));
}

bool ObjectStore::remove_object(const std::array<uint8_t, 32>& hash) const {
  return storage_.remove(object_key(hash));
}

void ObjectStore::write_object(const std::array<uint8_t, 32>& hash, const ByteVec& data) const {
  std::string key = object_key(hash);
  if (storage_.exists(key)) {
    return;
  }
  storage_.put(key, data, true);
}

void ObjectStore::write_object_from_file(const std::array<uint8_t, 32>& hash,
                                         const std::filesystem::path& path) const {
  std::string key = object_key(hash);
  if (storage_.exists(key)) {
    return;
  }

  ByteVec data = read_file_bytes(path);
  storage_.put(key, data, true);
}

ByteVec ObjectStore::read_object(const std::array<uint8_t, 32>& hash) const {
  std::string key = object_key(hash);
  if (!storage_.exists(key)) {
    throw std::runtime_error("object not found: " + root_ + "/" + key);
  }
  return storage_.get(key);
}
