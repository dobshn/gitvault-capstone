#include "vault.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include "crypto/ctr.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "crypto/sha256.h"
#include "util.h"

namespace {
constexpr size_t kIvSize = 16;
constexpr size_t kHeadCipherSize = 32;
constexpr size_t kHeadTagSize = 32;
constexpr const char* kStateFileName = ".gitvault_state";
constexpr size_t kChunkSize = 1 << 20;
constexpr uint64_t kProgressThresholdBytes = 16ull * 1024 * 1024;
constexpr uint64_t kProgressIntervalBytes = 64ull * 1024 * 1024;

struct EncryptedObject {
  ByteVec data;
  std::array<uint8_t, 32> hash;
};

struct TempFileGuard {
  std::filesystem::path path;
  bool active = true;

  ~TempFileGuard() {
    if (!active || path.empty()) {
      return;
    }
    std::error_code ec;
    std::filesystem::remove(path, ec);
  }
};

EncryptedObject encrypt_object(const ByteVec& enc_key, const ByteVec& plaintext) {
  ByteVec iv = random_bytes(kIvSize);
  ByteVec ciphertext = aes256_ctr_crypt(enc_key, iv, plaintext);
  ByteVec combined;
  combined.reserve(iv.size() + ciphertext.size());
  append_bytes(combined, iv.data(), iv.size());
  append_bytes(combined, ciphertext.data(), ciphertext.size());
  auto hash = Sha256::hash(combined);
  return {combined, hash};
}

void log_progress_line(const std::filesystem::path& path,
                       uint64_t processed,
                       uint64_t total,
                       const std::chrono::steady_clock::time_point& start) {
  double pct = total > 0 ? (static_cast<double>(processed) * 100.0 / static_cast<double>(total)) : 100.0;
  double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  double mbps = (elapsed > 0.0) ? (static_cast<double>(processed) / (1024.0 * 1024.0)) / elapsed : 0.0;
  std::ostringstream oss;
  oss << "Encrypting " << path.string() << ": " << processed << "/" << total << " bytes (";
  oss << std::fixed << std::setprecision(1) << pct << "%, " << mbps << " MB/s)";
  std::cerr << oss.str() << "\n";
}

ByteVec decrypt_object_checked(const ObjectStore& store,
                              const ByteVec& enc_key,
                              const std::array<uint8_t, 32>& expected_hash) {
  ByteVec data = store.read_object(expected_hash);
  auto actual_hash = Sha256::hash(data);
  if (!constant_time_equal(actual_hash, expected_hash)) {
    throw std::runtime_error("object hash mismatch: " + to_hex(expected_hash));
  }
  if (data.size() < kIvSize) {
    throw std::runtime_error("object too small: " + to_hex(expected_hash));
  }
  ByteVec iv(data.begin(), data.begin() + kIvSize);
  ByteVec ciphertext(data.begin() + kIvSize, data.end());
  return aes256_ctr_crypt(enc_key, iv, ciphertext);
}

void write_head(const ObjectStore& store, const Keys& keys, const std::array<uint8_t, 32>& commit_hash) {
  ByteVec iv = random_bytes(kIvSize);
  ByteVec plain(commit_hash.begin(), commit_hash.end());
  ByteVec cipher = aes256_ctr_crypt(keys.enc_key, iv, plain);
  ByteVec mac_input;
  mac_input.reserve(iv.size() + cipher.size());
  append_bytes(mac_input, iv.data(), iv.size());
  append_bytes(mac_input, cipher.data(), cipher.size());
  auto tag = hmac_sha256(keys.mac_key, mac_input);

  ByteVec out;
  out.reserve(iv.size() + cipher.size() + tag.size());
  append_bytes(out, iv.data(), iv.size());
  append_bytes(out, cipher.data(), cipher.size());
  append_bytes(out, tag.data(), tag.size());

  store.write_head(out);
}

std::array<uint8_t, 32> read_head(const ObjectStore& store, const Keys& keys) {
  ByteVec data = store.read_head();
  if (data.size() != kIvSize + kHeadCipherSize + kHeadTagSize) {
    throw std::runtime_error("invalid HEAD size");
  }
  ByteVec iv(data.begin(), data.begin() + kIvSize);
  ByteVec cipher(data.begin() + kIvSize, data.begin() + kIvSize + kHeadCipherSize);
  ByteVec tag(data.begin() + kIvSize + kHeadCipherSize, data.end());

  ByteVec mac_input;
  mac_input.reserve(iv.size() + cipher.size());
  append_bytes(mac_input, iv.data(), iv.size());
  append_bytes(mac_input, cipher.data(), cipher.size());
  auto expected = hmac_sha256(keys.mac_key, mac_input);

  ByteVec expected_vec(expected.begin(), expected.end());
  if (!constant_time_equal(expected_vec, tag)) {
    throw std::runtime_error("HEAD HMAC verification failed");
  }

  ByteVec plain = aes256_ctr_crypt(keys.enc_key, iv, cipher);
  if (plain.size() != 32) {
    throw std::runtime_error("invalid HEAD plaintext size");
  }
  std::array<uint8_t, 32> out{};
  std::copy(plain.begin(), plain.end(), out.begin());
  return out;
}

void write_state(const std::filesystem::path& state_path, const std::array<uint8_t, 32>& commit_hash) {
  if (!state_path.parent_path().empty()) {
    std::filesystem::create_directories(state_path.parent_path());
  }
  std::ofstream file(state_path, std::ios::trunc);
  if (!file) {
    throw std::runtime_error("failed to write state: " + state_path.string());
  }
  file << "version=1\n";
  file << "commit=" << to_hex(commit_hash) << "\n";
}

std::array<uint8_t, 32> read_state(const std::filesystem::path& state_path) {
  std::ifstream file(state_path);
  if (!file) {
    throw std::runtime_error("state not found: " + state_path.string());
  }
  std::string line;
  std::string commit_hex;
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
    if (key == "commit") {
      commit_hex = value;
    }
  }
  if (commit_hex.empty()) {
    throw std::runtime_error("state missing commit hash");
  }
  return hash_from_hex(commit_hex);
}

std::array<uint8_t, 32> resolve_commit_hash(const ObjectStore& store,
                                            const Keys& keys,
                                            const std::optional<std::filesystem::path>& state_path) {
  if (state_path.has_value()) {
    if (!std::filesystem::exists(state_path.value())) {
      throw std::runtime_error("state file not found: " + state_path.value().string());
    }
    return read_state(state_path.value());
  }
  return read_head(store, keys);
}

Commit load_commit_checked(const ObjectStore& store,
                           const Keys& keys,
                           const std::array<uint8_t, 32>& commit_hash) {
  ByteVec plaintext = decrypt_object_checked(store, keys.enc_key, commit_hash);
  return deserialize_commit(plaintext);
}

Tree load_tree_checked(const ObjectStore& store,
                       const Keys& keys,
                       const std::array<uint8_t, 32>& tree_hash) {
  ByteVec plaintext = decrypt_object_checked(store, keys.enc_key, tree_hash);
  return deserialize_tree(plaintext);
}

std::array<uint8_t, 32> store_blob(const std::filesystem::path& path,
                                  const ObjectStore& store,
                                  const Keys& keys) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open file for reading: " + path.string());
  }

  std::error_code ec;
  uint64_t total_size = std::filesystem::file_size(path, ec);
  if (ec) {
    total_size = 0;
  }

  bool log_progress = total_size >= kProgressThresholdBytes;
  auto start_time = std::chrono::steady_clock::now();
  auto last_log = start_time;
  uint64_t last_logged_bytes = 0;
  const auto log_interval = std::chrono::seconds(5);

  ByteVec iv = random_bytes(kIvSize);
  Sha256 hasher;
  hasher.update(iv.data(), iv.size());

  std::filesystem::path tmp_dir = std::filesystem::temp_directory_path() / "gitvault";
  std::filesystem::create_directories(tmp_dir);
  std::filesystem::path tmp_path = tmp_dir / ("obj_" + to_hex(random_bytes(8)) + ".tmp");
  TempFileGuard guard;
  guard.path = tmp_path;

  std::ofstream output(tmp_path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("failed to open temp object for writing: " + tmp_path.string());
  }
  output.write(reinterpret_cast<const char*>(iv.data()), static_cast<std::streamsize>(iv.size()));
  if (!output) {
    throw std::runtime_error("failed to write temp object header: " + tmp_path.string());
  }

  Aes256CtrStream stream(keys.enc_key, iv);
  ByteVec in_buf(kChunkSize);
  ByteVec out_buf(kChunkSize);
  uint64_t processed = 0;

  if (log_progress) {
    log_progress_line(path, 0, total_size, start_time);
  }

  while (input) {
    input.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(in_buf.size()));
    std::streamsize read = input.gcount();
    if (read <= 0) {
      break;
    }

    stream.crypt(in_buf.data(), static_cast<size_t>(read), out_buf.data());
    output.write(reinterpret_cast<const char*>(out_buf.data()), read);
    if (!output) {
      throw std::runtime_error("failed to write temp object: " + tmp_path.string());
    }

    hasher.update(out_buf.data(), static_cast<size_t>(read));
    processed += static_cast<uint64_t>(read);

    if (log_progress) {
      auto now = std::chrono::steady_clock::now();
      bool time_due = (now - last_log) >= log_interval;
      bool bytes_due = (processed - last_logged_bytes) >= kProgressIntervalBytes;
      if (time_due || bytes_due) {
        log_progress_line(path, processed, total_size, start_time);
        last_log = now;
        last_logged_bytes = processed;
      }
    }
  }

  if (!input.eof()) {
    throw std::runtime_error("failed to read file: " + path.string());
  }
  output.flush();
  output.close();
  if (!output) {
    throw std::runtime_error("failed to finalize temp object: " + tmp_path.string());
  }

  std::array<uint8_t, 32> hash = hasher.finalize();
  store.write_object_from_file(hash, tmp_path);
  guard.active = false;
  std::error_code rm_ec;
  std::filesystem::remove(tmp_path, rm_ec);

  if (log_progress && processed != last_logged_bytes) {
    log_progress_line(path, processed, total_size, start_time);
  }

  return hash;
}

std::array<uint8_t, 32> store_tree(const std::filesystem::path& dir,
                                  const ObjectStore& store,
                                  const Keys& keys,
                                  const std::filesystem::path& state_path) {
  Tree tree;
  std::vector<Entry> entries;

  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    const auto& path = entry.path();

    if (entry.is_symlink()) {
      continue;
    }

    if (path.filename() == kStateFileName) {
      continue;
    }

    if (!state_path.empty()) {
      std::error_code ec;
      if (std::filesystem::equivalent(path, state_path, ec) && !ec) {
        continue;
      }
    }

    Entry out;
    out.name = path.filename().string();

    if (entry.is_directory()) {
      out.type = 1;
      out.flags = 0x02;
      out.mtime = file_mtime_seconds(path);
      out.hash = store_tree(path, store, keys, state_path);
      entries.push_back(out);
      continue;
    }

    if (!entry.is_regular_file()) {
      continue;
    }

    out.type = 0;
    out.flags = 0x03;
    out.size = static_cast<uint64_t>(entry.file_size());
    out.mtime = file_mtime_seconds(path);
    out.hash = store_blob(path, store, keys);
    entries.push_back(out);
  }

  std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
    return a.name < b.name;
  });

  tree.entries = std::move(entries);
  ByteVec serialized = serialize_tree(tree);
  EncryptedObject obj = encrypt_object(keys.enc_key, serialized);
  store.write_object(obj.hash, obj.data);
  return obj.hash;
}

struct PathResult {
  bool is_directory = false;
  Tree tree;
  Entry entry;
};

PathResult resolve_path(const ObjectStore& store,
                        const Keys& keys,
                        const std::optional<std::filesystem::path>& state_path,
                        const std::string& path) {
  auto commit_hash = resolve_commit_hash(store, keys, state_path);
  Commit commit = load_commit_checked(store, keys, commit_hash);
  std::array<uint8_t, 32> current_hash = commit.root_hash;

  if (path.empty()) {
    PathResult result;
    result.is_directory = true;
    result.tree = load_tree_checked(store, keys, current_hash);
    return result;
  }

  std::vector<std::string> parts = split_path(path);
  for (size_t i = 0; i < parts.size(); ++i) {
    Tree tree = load_tree_checked(store, keys, current_hash);
    auto it = std::find_if(tree.entries.begin(), tree.entries.end(),
                           [&](const Entry& e) { return e.name == parts[i]; });
    if (it == tree.entries.end()) {
      throw std::runtime_error("path not found: " + path);
    }

    bool is_last = (i + 1 == parts.size());
    if (is_last) {
      PathResult result;
      result.is_directory = (it->type == 1);
      if (result.is_directory) {
        result.tree = load_tree_checked(store, keys, it->hash);
      } else {
        result.entry = *it;
      }
      return result;
    }

    if (it->type != 1) {
      throw std::runtime_error("path is not a directory: " + parts[i]);
    }
    current_hash = it->hash;
  }

  throw std::runtime_error("path resolution failed");
}

void scan_tree(const ObjectStore& store,
               const Keys& keys,
               const std::array<uint8_t, 32>& tree_hash,
               bool deep,
               ScanStats& stats) {
  Tree tree = load_tree_checked(store, keys, tree_hash);
  stats.trees_checked++;

  for (const auto& entry : tree.entries) {
    if (entry.type == 1) {
      scan_tree(store, keys, entry.hash, deep, stats);
      continue;
    }

    stats.blobs_checked++;
    if (!store.object_exists(entry.hash)) {
      stats.blobs_missing++;
      continue;
    }

    if (deep) {
      ByteVec data = store.read_object(entry.hash);
      auto actual_hash = Sha256::hash(data);
      if (!constant_time_equal(actual_hash, entry.hash)) {
        throw std::runtime_error("blob hash mismatch: " + to_hex(entry.hash));
      }
      stats.blobs_hashed++;
    }
  }
}

void print_tree_recursive(const ObjectStore& store,
                          const Keys& keys,
                          const Tree& tree,
                          const std::string& prefix,
                          std::ostream& out) {
  std::vector<Entry> entries = tree.entries;
  std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
    return a.name < b.name;
  });

  for (size_t i = 0; i < entries.size(); ++i) {
    const Entry& entry = entries[i];
    bool last = (i + 1 == entries.size());
    out << prefix << (last ? "`-- " : "|-- ") << entry.name;
    if (entry.type == 1) {
      out << "/";
    }
    out << "\n";

    if (entry.type == 1) {
      Tree child = load_tree_checked(store, keys, entry.hash);
      std::string next_prefix = prefix + (last ? "    " : "|   ");
      print_tree_recursive(store, keys, child, next_prefix, out);
    }
  }
}

std::array<uint8_t, 32> upsert_blob_to_tree(const ObjectStore& store,
                                            const Keys& keys,
                                            const std::array<uint8_t, 32>& tree_hash,
                                            const std::vector<std::string>& dirs,
                                            size_t depth,
                                            const Entry& blob_entry,
                                            uint64_t touch_time,
                                            std::vector<std::array<uint8_t, 32>>& old_tree_hashes) {
  old_tree_hashes.push_back(tree_hash);
  Tree tree = load_tree_checked(store, keys, tree_hash);

  if (depth == dirs.size()) {
    auto it = std::find_if(tree.entries.begin(), tree.entries.end(),
                           [&](const Entry& e) { return e.name == blob_entry.name; });
    if (it == tree.entries.end()) {
      tree.entries.push_back(blob_entry);
    } else {
      if (it->type == 1) {
        throw std::runtime_error("cloud_path points to existing directory: " + blob_entry.name);
      }
      *it = blob_entry;
    }
  } else {
    const std::string& dir_name = dirs[depth];
    auto it = std::find_if(tree.entries.begin(), tree.entries.end(),
                           [&](const Entry& e) { return e.name == dir_name; });
    if (it == tree.entries.end()) {
      throw std::runtime_error("path not found: " + dir_name);
    }
    if (it->type != 1) {
      throw std::runtime_error("not a directory: " + dir_name);
    }

    it->hash = upsert_blob_to_tree(store, keys, it->hash, dirs, depth + 1, blob_entry, touch_time, old_tree_hashes);
    it->flags |= 0x02;
    it->mtime = touch_time;
  }

  std::sort(tree.entries.begin(), tree.entries.end(), [](const Entry& a, const Entry& b) {
    return a.name < b.name;
  });

  ByteVec serialized = serialize_tree(tree);
  EncryptedObject obj = encrypt_object(keys.enc_key, serialized);
  store.write_object(obj.hash, obj.data);
  return obj.hash;
}

std::array<uint8_t, 32> remove_blob_from_tree(const ObjectStore& store,
                                              const Keys& keys,
                                              const std::array<uint8_t, 32>& tree_hash,
                                              const std::vector<std::string>& dirs,
                                              size_t depth,
                                              const std::string& blob_name,
                                              uint64_t touch_time,
                                              std::vector<std::array<uint8_t, 32>>& old_tree_hashes) {
  old_tree_hashes.push_back(tree_hash);
  Tree tree = load_tree_checked(store, keys, tree_hash);

  if (depth == dirs.size()) {
    auto it = std::find_if(tree.entries.begin(), tree.entries.end(),
                           [&](const Entry& e) { return e.name == blob_name; });
    if (it == tree.entries.end()) {
      throw std::runtime_error("path not found: " + blob_name);
    }
    if (it->type == 1) {
      throw std::runtime_error("cloud_path points to existing directory: " + blob_name);
    }
    tree.entries.erase(it);
  } else {
    const std::string& dir_name = dirs[depth];
    auto it = std::find_if(tree.entries.begin(), tree.entries.end(),
                           [&](const Entry& e) { return e.name == dir_name; });
    if (it == tree.entries.end()) {
      throw std::runtime_error("path not found: " + dir_name);
    }
    if (it->type != 1) {
      throw std::runtime_error("not a directory: " + dir_name);
    }

    it->hash = remove_blob_from_tree(store, keys, it->hash, dirs, depth + 1, blob_name, touch_time, old_tree_hashes);
    it->flags |= 0x02;
    it->mtime = touch_time;
  }

  std::sort(tree.entries.begin(), tree.entries.end(), [](const Entry& a, const Entry& b) {
    return a.name < b.name;
  });

  ByteVec serialized = serialize_tree(tree);
  EncryptedObject obj = encrypt_object(keys.enc_key, serialized);
  store.write_object(obj.hash, obj.data);
  return obj.hash;
}
}  // namespace

Config ensure_store_config(ObjectStore& store) {
  if (store.config_exists()) {
    return store.load_config();
  }
  Config cfg;
  cfg.salt = random_bytes(16);
  cfg.iterations = 100000;
  store.save_config(cfg);
  return cfg;
}

Keys derive_keys(const Config& config, const std::string& password) {
  ByteVec key_material = pbkdf2_hmac_sha256(password, config.salt, config.iterations, 64);
  Keys keys;
  keys.enc_key.assign(key_material.begin(), key_material.begin() + 32);
  keys.mac_key.assign(key_material.begin() + 32, key_material.end());
  return keys;
}

std::array<uint8_t, 32> lock_vault(const std::filesystem::path& plain_dir,
                                  ObjectStore& store,
                                  const Keys& keys,
                                  const std::filesystem::path& state_path) {
  if (!std::filesystem::exists(plain_dir) || !std::filesystem::is_directory(plain_dir)) {
    throw std::runtime_error("plain_dir must be a directory");
  }

  std::array<uint8_t, 32> root_hash = store_tree(plain_dir, store, keys, state_path);

  Commit commit;
  commit.commit_time = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  commit.root_hash = root_hash;

  ByteVec serialized = serialize_commit(commit);
  EncryptedObject obj = encrypt_object(keys.enc_key, serialized);
  store.write_object(obj.hash, obj.data);

  write_head(store, keys, obj.hash);
  write_state(state_path, obj.hash);

  return obj.hash;
}

Tree list_directory(const ObjectStore& store,
                    const Keys& keys,
                    const std::optional<std::filesystem::path>& state_path,
                    const std::string& path) {
  PathResult result = resolve_path(store, keys, state_path, path);
  if (!result.is_directory) {
    throw std::runtime_error("path is not a directory: " + path);
  }
  return result.tree;
}

Entry resolve_entry(const ObjectStore& store,
                    const Keys& keys,
                    const std::optional<std::filesystem::path>& state_path,
                    const std::string& path,
                    bool require_directory) {
  if (path.empty()) {
    throw std::runtime_error("path required");
  }
  PathResult result = resolve_path(store, keys, state_path, path);
  if (require_directory && !result.is_directory) {
    throw std::runtime_error("path is not a directory: " + path);
  }
  if (result.is_directory) {
    Entry entry;
    entry.type = 1;
    entry.name = path;
    return entry;
  }
  return result.entry;
}

ByteVec read_file_from_vault(const ObjectStore& store,
                             const Keys& keys,
                             const std::optional<std::filesystem::path>& state_path,
                             const std::string& path) {
  Entry entry = resolve_entry(store, keys, state_path, path, false);
  if (entry.type != 0) {
    throw std::runtime_error("path is not a file: " + path);
  }
  ByteVec plaintext = decrypt_object_checked(store, keys.enc_key, entry.hash);
  return plaintext;
}

ScanStats quick_scan(const ObjectStore& store,
                     const Keys& keys,
                     const std::optional<std::filesystem::path>& state_path) {
  auto commit_hash = resolve_commit_hash(store, keys, state_path);
  Commit commit = load_commit_checked(store, keys, commit_hash);
  ScanStats stats;
  scan_tree(store, keys, commit.root_hash, false, stats);
  return stats;
}

ScanStats deep_scan(const ObjectStore& store,
                    const Keys& keys,
                    const std::optional<std::filesystem::path>& state_path) {
  auto commit_hash = resolve_commit_hash(store, keys, state_path);
  Commit commit = load_commit_checked(store, keys, commit_hash);
  ScanStats stats;
  scan_tree(store, keys, commit.root_hash, true, stats);
  return stats;
}

void print_tree(const ObjectStore& store,
                const Keys& keys,
                const std::optional<std::filesystem::path>& state_path,
                const std::string& path,
                std::ostream& out) {
  PathResult result = resolve_path(store, keys, state_path, path);
  std::string label = path.empty() ? "." : path;
  out << label;
  if (result.is_directory && (label.empty() || label.back() != '/')) {
    out << "/";
  }
  out << "\n";
  if (result.is_directory) {
    print_tree_recursive(store, keys, result.tree, "", out);
  }
}

std::array<uint8_t, 32> add(const ObjectStore& store, const Keys& keys, const std::filesystem::path& local_path, const std::string& cloud_path) {
  // 인자가 비어있지 않은지 검사한 뒤, 로컬 파일이 일반 파일임을 검증한다.
  if (local_path.empty()) throw std::runtime_error("local_path required");
  if (cloud_path.empty()) throw std::runtime_error("cloud_path required");
  if (!std::filesystem::exists(local_path) || !std::filesystem::is_regular_file(local_path)) throw std::runtime_error("local_path must be a regular file: " + local_path.string());

  // 로컬 파일을 blob으로 만들어 업로드한 뒤, 새로 추가된 blob의 object id를 저장한다.
  std::array<uint8_t, 32> uploaded_object_id = store_blob(local_path, store, keys);

  // cloud_path를 분해하고 마지막 요소를 파일명으로 쓴다.
  std::vector<std::string> parts = split_path(cloud_path);
  if (parts.empty()) throw std::runtime_error("invalid cloud_path: " + cloud_path);
  const std::string file_name = parts.back();
  parts.pop_back();

  // 현재 HEAD 기준 commit을 가져온다.
  auto commit_hash = resolve_commit_hash(store, keys, std::nullopt);
  Commit commit = load_commit_checked(store, keys, commit_hash);

  // leaf에 넣을 파일 엔트리를 만든다.
  std::error_code ec;
  uint64_t file_size = std::filesystem::file_size(local_path, ec);
  if (ec) throw std::runtime_error("failed to get local file size: " + local_path.string());

  uint64_t now_sec = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());

  Entry file_entry;
  file_entry.type = 0;
  file_entry.flags = 0x03;
  file_entry.name = file_name;
  file_entry.hash = uploaded_object_id;
  file_entry.size = file_size;
  file_entry.mtime = file_mtime_seconds(local_path);

  // 루트에서 내려갔다가 올라오면서 tree hash를 한 번에 갱신한다.
  std::vector<std::array<uint8_t, 32>> old_tree_hashes;
  std::array<uint8_t, 32> new_root_hash =
      upsert_blob_to_tree(store, keys, commit.root_hash, parts, 0, file_entry, now_sec, old_tree_hashes);

  // 새 root tree로 commit/HEAD를 갱신한다.
  Commit new_commit = commit;
  new_commit.commit_time = now_sec;
  new_commit.root_hash = new_root_hash;
  ByteVec serialized_commit = serialize_commit(new_commit);
  EncryptedObject commit_obj = encrypt_object(keys.enc_key, serialized_commit);
  store.write_object(commit_obj.hash, commit_obj.data);
  write_head(store, keys, commit_obj.hash);

  // 이전 commit 객체를 삭제한다.
  if (!store.remove_object(commit_hash)) {
    throw std::runtime_error("failed to delete old commit object: " + to_hex(commit_hash));
  }

  // 이전 tree 객체들을 삭제한다.
  for (const auto& old_hash : old_tree_hashes) {
    try {
      store.remove_object(old_hash);
    } catch (const std::exception& ex) {
      std::cerr << "warning: failed to delete old tree object " << to_hex(old_hash)
                << ": " << ex.what() << "\n";
    }
  }

  return commit_obj.hash;
}

// TODO: 디렉토리 삭제 정책 결정 및 구현 필요. 현재는 파일만 삭제 가능
std::array<uint8_t, 32> remove(const ObjectStore& store, const Keys& keys, const std::string& cloud_path) {
  // 인자가 비어있지 않은지 검사한 뒤, cloud_path를 분해해 대상 파일명을 추출한다.
  if (cloud_path.empty()) throw std::runtime_error("cloud_path required");
  Entry removed_entry = resolve_entry(store, keys, std::nullopt, cloud_path, false);
  if (removed_entry.type != 0) throw std::runtime_error("path is not a file: " + cloud_path);
  std::array<uint8_t, 32> removed_blob_hash = removed_entry.hash;

  std::vector<std::string> parts = split_path(cloud_path);
  if (parts.empty()) throw std::runtime_error("invalid cloud_path: " + cloud_path);
  const std::string file_name = parts.back();
  parts.pop_back();

  // 현재 HEAD 기준 commit을 가져온다.
  auto commit_hash = resolve_commit_hash(store, keys, std::nullopt);
  Commit commit = load_commit_checked(store, keys, commit_hash);

  uint64_t now_sec = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());

  // 루트에서 내려갔다가 올라오면서 대상 파일을 제거한 tree hash를 재계산한다.
  std::vector<std::array<uint8_t, 32>> old_tree_hashes;
  std::array<uint8_t, 32> new_root_hash =
      remove_blob_from_tree(store, keys, commit.root_hash, parts, 0, file_name, now_sec, old_tree_hashes);

  // 새 root tree로 commit/HEAD를 갱신한다.
  Commit new_commit = commit;
  new_commit.commit_time = now_sec;
  new_commit.root_hash = new_root_hash;
  ByteVec serialized_commit = serialize_commit(new_commit);
  EncryptedObject commit_obj = encrypt_object(keys.enc_key, serialized_commit);
  store.write_object(commit_obj.hash, commit_obj.data);
  write_head(store, keys, commit_obj.hash);

  // 이전 commit 객체를 삭제한다.
  if (!store.remove_object(commit_hash)) {
    throw std::runtime_error("failed to delete old commit object: " + to_hex(commit_hash));
  }

  // 이전 tree 객체들을 삭제한다.
  for (const auto& old_hash : old_tree_hashes) {
    try {
      store.remove_object(old_hash);
    } catch (const std::exception& ex) {
      std::cerr << "warning: failed to delete old tree object " << to_hex(old_hash)
                << ": " << ex.what() << "\n";
    }
  }

  // 삭제 대상 blob 객체를 삭제한다.
  if (!store.remove_object(removed_blob_hash)) {
    throw std::runtime_error("failed to delete old blob object: " + to_hex(removed_blob_hash));
  }

  return commit_obj.hash;
}
