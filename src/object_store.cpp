#include "object_store.h"
#include "vault_identity.h"

#include <fstream>
#include <iostream>
#include <cerrno>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {
  constexpr const char* kConfigKey = "config";
  constexpr const char* kHeadKey = "HEAD";

void write_local_atomic(const std::filesystem::path& path,
                        const ByteVec& data) {
  std::filesystem::create_directories(path.parent_path());
  std::filesystem::path temporary = path;
  temporary += ".tmp-" + to_hex(random_bytes(8));
#if !defined(_WIN32)
  const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    throw std::runtime_error("failed to create local temporary file: " +
                             std::string(std::strerror(errno)));
  }
  bool open = true;
  try {
    size_t offset = 0;
    while (offset < data.size()) {
      const ssize_t written = ::write(
          fd, data.data() + offset, data.size() - offset);
      if (written <= 0) {
        throw std::runtime_error("failed to write local temporary file");
      }
      offset += static_cast<size_t>(written);
    }
    if (::fsync(fd) != 0) {
      throw std::runtime_error("failed to fsync local temporary file");
    }
    ::close(fd);
    open = false;
    std::filesystem::rename(temporary, path);
    const int directory_fd =
        ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
    if (directory_fd < 0 || ::fsync(directory_fd) != 0) {
      if (directory_fd >= 0) ::close(directory_fd);
      throw std::runtime_error("failed to fsync local metadata directory");
    }
    ::close(directory_fd);
  } catch (...) {
    if (open) ::close(fd);
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    throw;
  }
#else
  write_file_bytes(temporary, data);
  std::filesystem::rename(temporary, path);
#endif
}

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
  if (local_metadata_root_.has_value()) {
    return *local_metadata_root_ / vault_name;
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

std::filesystem::path ObjectStore::vault_identity_path() const {
  return metadata_dir() / "trust" / "vault-identity.enc";
}

// 생성자
ObjectStore::ObjectStore() {
  CloudAPI = std::make_unique<DropboxStorage>();
}

ObjectStore::ObjectStore(std::unique_ptr<API> cloud_api)
    : CloudAPI(std::move(cloud_api)) {
  if (!CloudAPI) {
    throw std::runtime_error("cloud API must not be null");
  }
}

ObjectStore::ObjectStore(std::unique_ptr<API> cloud_api,
                         std::filesystem::path local_metadata_root)
    : local_metadata_root_(std::move(local_metadata_root)),
      CloudAPI(std::move(cloud_api)) {
  if (!CloudAPI || local_metadata_root_->empty()) {
    throw std::runtime_error("cloud API and local metadata root are required");
  }
}

void ObjectStore::fetch(std::string access_token, std::string root_path) {
  root_ = normalize_root_path(std::move(root_path));
  CloudAPI->fetch(access_token, root_);
}

void ObjectStore::init(std::string access_token, std::string root_path) {
  root_ = normalize_root_path(std::move(root_path));
  CloudAPI->init(access_token, root_);
}

bool ObjectStore::destroy(std::string access_token, std::string root_path) {
  root_ = normalize_root_path(std::move(root_path));
  return CloudAPI->destroy(access_token, root_);
}

const std::string& ObjectStore::root() const {
  return root_;
}

std::filesystem::path ObjectStore::trust_directory() const {
  return metadata_dir() / "trust";
}

std::filesystem::path ObjectStore::local_metadata_directory() const {
  return metadata_dir();
}

bool ObjectStore::remove_local_metadata() const {
  const std::filesystem::path path = metadata_dir();
  if (!std::filesystem::exists(path)) {
    return false;
  }

  std::error_code ec;
  const auto removed = std::filesystem::remove_all(path, ec);
  if (ec) {
    throw std::runtime_error("failed to remove local metadata: " + path.string());
  }
  return removed > 0;
}

bool ObjectStore::config_exists() const {
  return std::filesystem::exists(config_path());
}

Config ObjectStore::load_config() const {
  if (!std::filesystem::exists(config_path())) {
      try {
          ByteVec data = CloudAPI->get("config");
          write_file_bytes(config_path(), data);  // <- 여기
          std::cout << "Local config not found. Using cloud config file." << std::endl;
      } catch (...) {
          throw std::runtime_error("config not found locally or in cloud");
      }
  }
  std::ifstream file(config_path());
  if (!file) {
    throw std::runtime_error("config not found: " + config_path().string());
  }

  Config cfg;
  cfg.version = 0;
  cfg.iterations = 0;
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
      const unsigned long parsed_version = std::stoul(value);
      if (parsed_version > 255) {
        throw std::runtime_error("invalid config version");
      }
      cfg.version = static_cast<uint8_t>(parsed_version);
    } else if (key == "kdf_salt") {
      cfg.salt = from_hex(value);
    } else if (key == "kdf_iter") {
      const unsigned long parsed_iterations = std::stoul(value);
      if (parsed_iterations > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("invalid config kdf_iter");
      }
      cfg.iterations = static_cast<uint32_t>(parsed_iterations);
    }
  }

  if (cfg.version == 0) {
    throw std::runtime_error("config missing version");
  }
  if (cfg.version != 2) {
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

  file << "version=2\n";
  file << "kdf=pbkdf2-hmac-sha256\n";
  file << "kdf_iter=" << config.iterations << "\n";
  file << "kdf_salt=" << to_hex(config.salt) << "\n";
  file << "key_schedule=pbkdf2-master-hkdf-sha256-v2\n";
  file << "enc=aes-256-ctr\n";

  file.close();  // 중요: flush

  // 파일 읽어서 클라우드 업로드
  ByteVec data = read_file_bytes(path);
  CloudAPI->put("config", data, true);
}

ByteVec ObjectStore::read_local_config_bytes() const {
  if (!std::filesystem::exists(config_path())) {
    throw std::runtime_error("local config not found: " +
                             config_path().string());
  }
  return read_file_bytes(config_path());
}

ByteVec ObjectStore::read_cloud_config_bytes() const {
  return CloudAPI->get(kConfigKey);
}

void ObjectStore::write_local_config_bytes(const ByteVec& bytes) const {
  if (bytes.empty()) {
    throw std::runtime_error("refusing to install an empty config");
  }
  const auto path = config_path();
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("local config already exists: " + path.string());
  }
  write_local_atomic(path, bytes);
}

void ObjectStore::install_initial_head(const ByteVec& data) const {
  const ConditionalWriteResult result = create_cloud_head(data);
  if (result.status != ConditionalWriteStatus::Updated) {
    throw std::runtime_error(
        "initial cloud HEAD already exists; refusing to overwrite it");
  }
  write_local_head(data);
}

ByteVec ObjectStore::read_head() const {
    const auto local_head = head_path();

    //먼저 로컬 확인
    if (std::filesystem::exists(local_head)) {
        ByteVec local_data = read_file_bytes(local_head);
        ByteVec cloud_data = CloudAPI->get(kHeadKey);
        if (!constant_time_equal(local_data, cloud_data)) {
            throw std::runtime_error(
                "local HEAD does not match cloud HEAD; possible rollback or unsynchronized state");
        }
        return local_data;
    }

    /*로컬 없으면 클라우드 확인
    if (CloudAPI->exists(kHeadKey)) {
        std::cerr << "Local HEAD not found at " << local_head.string()
                  << ", falling back to cloud HEAD\n";

        ByteVec cloud_head = CloudAPI->get(kHeadKey);
        std::cerr << "Downloaded HEAD size: " << cloud_head.size() << "\n";

        //로컬 캐싱 시도
        try {
            write_file_bytes(local_head, cloud_head);
        } catch (const std::exception& ex) {
            std::cerr << "Warning: failed to cache HEAD locally at "
                      << local_head.string() << ": " << ex.what() << "\n";
        }

        return cloud_head;
    }
    */
    throw std::runtime_error("If this vault was initialized on another device, try \"sync\" command");
}

ByteVec ObjectStore::read_local_head() const {
  const std::filesystem::path local_head = head_path();
  if (!std::filesystem::exists(local_head)) {
    throw std::runtime_error("local HEAD not found: " + local_head.string());
  }
  return read_file_bytes(local_head);
}

void ObjectStore::write_local_head(const ByteVec& data) const {
  write_local_atomic(head_path(), data);
}

VersionedBytes ObjectStore::read_cloud_head_versioned() const {
  return CloudAPI->get_versioned(kHeadKey);
}

ConditionalWriteResult ObjectStore::compare_exchange_cloud_head(
    const ByteVec& data,
    std::string_view expected_revision) const {
  return CloudAPI->put_if_revision(kHeadKey, data, expected_revision);
}

ConditionalWriteResult ObjectStore::create_cloud_head(
    const ByteVec& data) const {
  return CloudAPI->put_if_absent(kHeadKey, data);
}

bool ObjectStore::vault_identity_exists() const {
  return std::filesystem::exists(vault_identity_path());
}

void ObjectStore::save_vault_identity(const ByteVec& wrapped_identity) const {
  save_wrapped_vault_identity_file(vault_identity_path(), wrapped_identity);
}

ByteVec ObjectStore::load_vault_identity() const {
  return load_wrapped_vault_identity_file(vault_identity_path());
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
  const ConditionalWriteResult result = CloudAPI->put_if_absent(key, data);
  if (result.status == ConditionalWriteStatus::Updated) {
    return;
  }
  const ByteVec existing = CloudAPI->get(key);
  if (!constant_time_equal(existing, data)) {
    throw std::runtime_error("immutable object conflict: " + key);
  }
}

void ObjectStore::write_object_from_file(const std::array<uint8_t, 32>& hash,
                                         const std::filesystem::path& path) const {
  std::string key = object_key(hash);
  ByteVec data = read_file_bytes(path);
  write_object(hash, data);
}

ByteVec ObjectStore::read_object(const std::array<uint8_t, 32>& hash) const {
  std::string key = object_key(hash);
  if (!CloudAPI->exists(key)) {
    throw std::runtime_error(    "object not found: " + root_ + "/" + key);
  }
  return CloudAPI->get(key);
}
