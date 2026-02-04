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

  write_file_bytes(store.head_path(), out);
}

std::array<uint8_t, 32> read_head(const ObjectStore& store, const Keys& keys) {
  ByteVec data = read_file_bytes(store.head_path());
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

  std::filesystem::path tmp_dir = store.root() / "tmp";
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
  std::filesystem::path final_path = store.object_path(hash);
  if (std::filesystem::exists(final_path)) {
    guard.active = false;
    std::error_code rm_ec;
    std::filesystem::remove(tmp_path, rm_ec);
  } else {
    std::filesystem::create_directories(final_path.parent_path());
    std::filesystem::rename(tmp_path, final_path);
    guard.active = false;
  }

  if (log_progress && processed != last_logged_bytes) {
    log_progress_line(path, processed, total_size, start_time);
  }

  return hash;
}

std::array<uint8_t, 32> store_tree(const std::filesystem::path& dir,
                                  const ObjectStore& store,
                                  const Keys& keys,
                                  const std::filesystem::path& state_path,
                                  const std::optional<std::filesystem::path>& skip_store) {
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

    if (skip_store.has_value() && is_descendant_path(skip_store.value(), path)) {
      continue;
    }

    Entry out;
    out.name = path.filename().string();

    if (entry.is_directory()) {
      out.type = 1;
      out.flags = 0x02;
      out.mtime = file_mtime_seconds(path);
      out.hash = store_tree(path, store, keys, state_path, skip_store);
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

  std::optional<std::filesystem::path> skip_store;
  std::error_code ec;
  if (std::filesystem::equivalent(plain_dir, store.root(), ec) && !ec) {
    throw std::runtime_error("store_dir must not be the same as plain_dir");
  }
  if (is_descendant_path(plain_dir, store.root())) {
    skip_store = store.root();
  }

  std::array<uint8_t, 32> root_hash = store_tree(plain_dir, store, keys, state_path, skip_store);

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
