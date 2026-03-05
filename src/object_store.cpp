#include "object_store.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace {
  constexpr const char* kConfigKey = "config";
  constexpr const char* kHeadKey = "HEAD";

std::string normalize_root_path(std::string root_path) {
    if (root_path.empty()) {
      throw std::runtime_error("invalid root path: empty");
    }
    if (root_path.front() != '/') {
      root_path.insert(root_path.begin(), '/');
    }
    while (root_path.size() > 1 && root_path.back() == '/') {
      root_path.pop_back();
    }
    if (root_path.size() < 2 || root_path.find("//") != std::string::npos) {
      throw std::runtime_error("invalid root path: use format like \"/my_root\"");
    }
    return root_path;
  }
}

std::filesystem::path ObjectStore::metadata_dir() const {
  std::filesystem::path vault_name = std::filesystem::path(root_).filename();
  if (vault_name.empty()) {
    throw std::runtime_error("invalid store root: " + root_);
  }
  // 로컬 메타데이터 위치: ~/.gitvault/<vault_name>/
  return std::filesystem::path(getHomeDirectory()) / ".gitvault" / vault_name;
}

std::filesystem::path ObjectStore::config_path() const {
  return metadata_dir() / kConfigKey;
}

std::filesystem::path ObjectStore::head_path() const {
  return metadata_dir() / kHeadKey;
}

// 생성자
ObjectStore::ObjectStore() {
  CloudAPI = new DropboxStorage();
}

// 소멸자
ObjectStore::~ObjectStore() {
  delete CloudAPI;
}

void ObjectStore::fetch(std::string access_token, std::string root_path) {
  root_ = normalize_root_path(std::move(root_path));
  CloudAPI->fetch(access_token, root_);
}

void ObjectStore::init(std::string access_token, std::string root_path) {
  root_ = normalize_root_path(std::move(root_path));
  CloudAPI->init(access_token, root_);
}

const std::string& ObjectStore::root() const {
  return root_;
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
  const std::filesystem::path path = config_path();
  std::filesystem::create_directories(path.parent_path());

  std::ofstream file(path, std::ios::trunc);
  if (!file) {
    throw std::runtime_error("failed to write config: " + path.string());
  }

  file << "version=1\n";
  file << "kdf=pbkdf2-hmac-sha256\n";
  file << "kdf_iter=" << config.iterations << "\n";
  file << "kdf_salt=" << to_hex(config.salt) << "\n";
  file << "enc=aes-256-ctr\n";
}

void ObjectStore::write_head(const ByteVec& data) const {
  const std::filesystem::path local_head = head_path();
  std::filesystem::create_directories(local_head.parent_path());
  write_file_bytes(local_head, data);

  CloudAPI->put(kHeadKey, data, true);
}

ByteVec ObjectStore::read_head() const {
  const std::filesystem::path local_head = head_path();
  if (std::filesystem::exists(local_head)) {
    return read_file_bytes(local_head);
  }

  if (CloudAPI->exists(kHeadKey)) {
    std::cerr << "warning: local HEAD not found at " << local_head.string()
              << ", falling back to cloud HEAD\n";
    ByteVec cloud_head = CloudAPI->get(kHeadKey);
    try {
      write_file_bytes(local_head, cloud_head);
    } catch (const std::exception& ex) {
      std::cerr << "warning: failed to cache HEAD locally at " << local_head.string()
                << ": " << ex.what() << "\n";
    }
    return cloud_head;
  }

  throw std::runtime_error("HEAD not found in local or cloud");
}

std::string ObjectStore::object_key(const std::array<uint8_t, 32>& hash) const {
  std::string hex = to_hex(hash);
  if (hex.size() != 64) {
    throw std::runtime_error("invalid hash length");
  }
  return "objects/" + hex;
}

bool ObjectStore::object_exists(const std::array<uint8_t, 32>& hash) const {
  return CloudAPI->exists(object_key(hash));
}

bool ObjectStore::remove_object(const std::array<uint8_t, 32>& hash) const {
  return CloudAPI->remove(object_key(hash));
}

void ObjectStore::write_object(const std::array<uint8_t, 32>& hash, const ByteVec& data) const {
  std::string key = object_key(hash);
  if (CloudAPI->exists(key)) {
    return;
  }
  CloudAPI->put(key, data, true);
}

void ObjectStore::write_object_from_file(const std::array<uint8_t, 32>& hash,
                                         const std::filesystem::path& path) const {
  std::string key = object_key(hash);
//  if (CloudAPI->exists(key)) {
//    return;
//  }

  ByteVec data = read_file_bytes(path);
  CloudAPI->put(key, data, true);
}

ByteVec ObjectStore::read_object(const std::array<uint8_t, 32>& hash) const {
  std::string key = object_key(hash);
  if (!CloudAPI->exists(key)) {
    throw std::runtime_error("object not found: " + root_ + "/" + key);
  }
  return CloudAPI->get(key);
}
