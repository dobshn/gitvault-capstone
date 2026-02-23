#include "vault_engine.h"
#include "crypto/ctr.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "crypto/sha256.h"
#include "crypto/CryptoImpl.h"
#include "crypto/ICrypto.h"
#include "object_store.h"
#include "util.h"

#include <fstream>
#include <algorithm>
#include <chrono>
#include <cstring>

namespace {
    constexpr size_t kIvSize = 16;
    constexpr size_t kHeadCipherSize = 32;
    constexpr size_t kHeadTagSize = 32;
    constexpr size_t kChunkSize = 1 << 20;
    constexpr uint64_t kProgressThresholdBytes = 16ull * 1024 * 1024;
    constexpr uint64_t kProgressIntervalBytes = 64ull * 1024 * 1024;
}

VaultEngine::VaultEngine(ObjectStore& s, std::string password) : store(s) {
    crypto = new CryptoImpl();
    cfg = ensure_store_config(store);
    keys = crypto->derive_keys(cfg.salt, cfg.iterations, password);
}

VaultEngine::~VaultEngine() {
    delete crypto;
}

std::array<uint8_t, 32> VaultEngine::init_vault() {
    Tree empty_tree;

    std::array<uint8_t, 32> root_hash = store_tree_object(empty_tree);
    std::cout << "kdf_salt=" << to_hex(cfg.salt) << "\n";
    return store_commit(root_hash, unix_time_seconds());
}

std::array<uint8_t, 32> VaultEngine::lock_vault(const std::filesystem::path& plain_dir) {
  if (!std::filesystem::exists(plain_dir) || !std::filesystem::is_directory(plain_dir)) {
    throw std::runtime_error("plain_dir must be a directory");
  }

  std::array<uint8_t, 32> root_hash = store_tree(plain_dir);
  return store_commit(root_hash, unix_time_seconds());
}

Tree VaultEngine::list_directory(const std::string& path) {
  PathResult result = resolve_path(path);
  if (!result.is_directory) {
    throw std::runtime_error("path is not a directory: " + path);
  }
  return result.tree;
}

Entry VaultEngine::resolve_entry(const std::string& path, bool require_directory) {
  if (path.empty()) {
    throw std::runtime_error("path required");
  }
  PathResult result = resolve_path(path);
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

ByteVec VaultEngine::read_file_from_vault(const std::string& path) {
  Entry entry = resolve_entry(path, false);
  if (entry.type != 0) {
    throw std::runtime_error("path is not a file: " + path);
  }
  ByteVec data = store.read_object(entry.hash);
  ByteVec plaintext = crypto->decrypt_object_checked(keys.enc_key, data, entry.hash);
  return plaintext;
}

ScanStats VaultEngine::quick_scan() {
  auto commit_hash = resolve_commit_hash();
  Commit commit = load_commit_checked(commit_hash);
  ScanStats stats;
  scan_tree(commit.root_hash, false, stats);
  return stats;
}

ScanStats VaultEngine::deep_scan() {
  auto commit_hash = resolve_commit_hash();
  Commit commit = load_commit_checked(commit_hash);
  ScanStats stats;
  scan_tree(commit.root_hash, true, stats);
  return stats;
}

void VaultEngine::print_tree(const std::string& path, std::ostream& out) {
  PathResult result = resolve_path(path);
  std::string label = path.empty() ? "." : path;
  out << label;
  if (result.is_directory && (label.empty() || label.back() != '/')) {
    out << "/";
  }
  out << "\n";
  if (result.is_directory) {
    print_tree_recursive(result.tree, "", out);
  }
}

std::array<uint8_t, 32> VaultEngine::add(const std::filesystem::path& local_path, const std::string& cloud_path) {
  if (local_path.empty()) {
    throw std::runtime_error("local_path required");
  }
  if (cloud_path.empty()) {
    throw std::runtime_error("cloud_path required");
  }
  if (!std::filesystem::exists(local_path) || !std::filesystem::is_regular_file(local_path)) {
    throw std::runtime_error("local_path must be a regular file: " + local_path.string());
  }

  std::array<uint8_t, 32> uploaded_object_id = store_blob(local_path);
  std::vector<std::string> parts = split_path(cloud_path);
  if (parts.empty()) {
    throw std::runtime_error("invalid cloud_path: " + cloud_path);
  }

  const std::string file_name = parts.back();
  parts.pop_back();

  auto old_commit_hash = resolve_commit_hash();
  Commit old_commit = load_commit_checked(old_commit_hash);

  std::error_code ec;
  uint64_t file_size = std::filesystem::file_size(local_path, ec);
  if (ec) {
    throw std::runtime_error("failed to get local file size: " + local_path.string());
  }

  uint64_t now_sec = unix_time_seconds();

  Entry file_entry;
  file_entry.type = 0;
  file_entry.flags = 0x03;
  file_entry.name = file_name;
  file_entry.hash = uploaded_object_id;
  file_entry.size = file_size;
  file_entry.mtime = file_mtime_seconds(local_path);

  std::vector<std::array<uint8_t, 32>> old_tree_hashes;
  std::array<uint8_t, 32> new_root_hash =
      upsert_blob_to_tree(old_commit.root_hash, parts, 0, file_entry, now_sec, old_tree_hashes);
  std::array<uint8_t, 32> new_commit_hash = store_commit(new_root_hash, now_sec);

  if (!store.remove_object(old_commit_hash)) {
    throw std::runtime_error("failed to delete old commit object: " + to_hex(old_commit_hash));
  }

  for (const auto& old_hash : old_tree_hashes) {
    try {
      store.remove_object(old_hash);
    } catch (const std::exception& ex) {
      std::cerr << "warning: failed to delete old tree object " << to_hex(old_hash)
                << ": " << ex.what() << "\n";
    }
  }

  return new_commit_hash;
}

std::array<uint8_t, 32> VaultEngine::remove(const std::string& cloud_path) {
  if (cloud_path.empty()) {
    throw std::runtime_error("cloud_path required");
  }

  Entry removed_entry = resolve_entry(cloud_path, false);
  if (removed_entry.type != 0) {
    throw std::runtime_error("path is not a file: " + cloud_path);
  }
  std::array<uint8_t, 32> removed_blob_hash = removed_entry.hash;

  std::vector<std::string> parts = split_path(cloud_path);
  if (parts.empty()) {
    throw std::runtime_error("invalid cloud_path: " + cloud_path);
  }
  const std::string file_name = parts.back();
  parts.pop_back();

  auto old_commit_hash = resolve_commit_hash();
  Commit old_commit = load_commit_checked(old_commit_hash);

  uint64_t now_sec = unix_time_seconds();
  std::vector<std::array<uint8_t, 32>> old_tree_hashes;
  std::array<uint8_t, 32> new_root_hash =
      remove_blob_from_tree(old_commit.root_hash, parts, 0, file_name, now_sec, old_tree_hashes);
  std::array<uint8_t, 32> new_commit_hash = store_commit(new_root_hash, now_sec);

  if (!store.remove_object(old_commit_hash)) {
    throw std::runtime_error("failed to delete old commit object: " + to_hex(old_commit_hash));
  }

  for (const auto& old_hash : old_tree_hashes) {
    try {
      store.remove_object(old_hash);
    } catch (const std::exception& ex) {
      std::cerr << "warning: failed to delete old tree object " << to_hex(old_hash)
                << ": " << ex.what() << "\n";
    }
  }

  if (!store.remove_object(removed_blob_hash)) {
    throw std::runtime_error("failed to delete old blob object: " + to_hex(removed_blob_hash));
  }

  return new_commit_hash;
}

// 내부함수
Config VaultEngine::ensure_store_config(ObjectStore& store) {
  if (store.config_exists()) {
    return store.load_config();
  }
  Config cfg;
  cfg.salt = random_bytes(16);
  cfg.iterations = 100000;
  store.save_config(cfg);
  return cfg;
}

  uint64_t VaultEngine::unix_time_seconds() {
      return static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()
          ).count()
      );
  }

  void VaultEngine::log_progress_line(const std::filesystem::path& path,
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

  void VaultEngine::write_head(const std::array<uint8_t, 32>& commit_hash) {
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

  std::array<uint8_t, 32> VaultEngine::read_head() {
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

  std::array<uint8_t, 32> VaultEngine::store_commit(const std::array<uint8_t, 32>& root_hash,
                                      uint64_t commit_time) {
    Commit commit;
    commit.commit_time = commit_time;
    commit.root_hash = root_hash;

    ByteVec serialized = serialize_commit(commit);
    EncryptedObject obj = crypto->encrypt_object(keys.enc_key, serialized);
    store.write_object(obj.hash, obj.data);
    write_head(obj.hash);
    return obj.hash;
  }

  std::array<uint8_t, 32> VaultEngine::store_tree_object(const Tree& tree) {
    ByteVec serialized = serialize_tree(tree);
    EncryptedObject obj = crypto->encrypt_object(keys.enc_key, serialized);
    store.write_object(obj.hash, obj.data);
    return obj.hash;
  }

  std::array<uint8_t, 32> VaultEngine::resolve_commit_hash() {
    return read_head();
  }

  Commit VaultEngine::load_commit_checked(const std::array<uint8_t, 32>& commit_hash) {
    ByteVec data = store.read_object(commit_hash);
    ByteVec plaintext = crypto->decrypt_object_checked(keys.enc_key, data, commit_hash);
    return deserialize_commit(plaintext);
  }

  Tree VaultEngine::load_tree_checked(const std::array<uint8_t, 32>& tree_hash) {
    ByteVec data = store.read_object(tree_hash);
    ByteVec plaintext = crypto->decrypt_object_checked(keys.enc_key, data, tree_hash);
    return deserialize_tree(plaintext);
  }

  std::array<uint8_t, 32> VaultEngine::store_blob(const std::filesystem::path& path) {
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

  std::array<uint8_t, 32> VaultEngine::store_tree(const std::filesystem::path& dir) {
    Tree tree;
    std::vector<Entry> entries;

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
      const auto& path = entry.path();

      if (entry.is_symlink()) {
        continue;
      }

      Entry out;
      out.name = path.filename().string();

      if (entry.is_directory()) {
        out.type = 1;
        out.flags = 0x02;
        out.mtime = file_mtime_seconds(path);
        out.hash = store_tree(path);
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
      out.hash = store_blob(path);
      entries.push_back(out);
    }

    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
      return a.name < b.name;
    });

    tree.entries = std::move(entries);
    return store_tree_object(tree);
  }

  PathResult VaultEngine::resolve_path(const std::string& path) {
    auto commit_hash = resolve_commit_hash();
    Commit commit = load_commit_checked(commit_hash);
    std::array<uint8_t, 32> current_hash = commit.root_hash;

    if (path.empty()) {
      PathResult result;
      result.is_directory = true;
      result.tree = load_tree_checked(current_hash);
      return result;
    }

    std::vector<std::string> parts = split_path(path);
    for (size_t i = 0; i < parts.size(); ++i) {
      Tree tree = load_tree_checked(current_hash);
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
          result.tree = load_tree_checked(it->hash);
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

  void VaultEngine::scan_tree(const std::array<uint8_t, 32>& tree_hash,
                bool deep,
                ScanStats& stats) {
    Tree tree = load_tree_checked(tree_hash);
    stats.trees_checked++;

    for (const auto& entry : tree.entries) {
      if (entry.type == 1) {
        scan_tree(entry.hash, deep, stats);
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

  void VaultEngine::print_tree_recursive(const Tree& tree,
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
        Tree child = load_tree_checked(entry.hash);
        std::string next_prefix = prefix + (last ? "    " : "|   ");
        print_tree_recursive(child, next_prefix, out);
      }
    }
  }

  std::array<uint8_t, 32> VaultEngine::upsert_blob_to_tree(const std::array<uint8_t, 32>& tree_hash,
                                              const std::vector<std::string>& dirs,
                                              size_t depth,
                                              const Entry& blob_entry,
                                              uint64_t touch_time,
                                              std::vector<std::array<uint8_t, 32>>& old_tree_hashes) {
    old_tree_hashes.push_back(tree_hash);
    Tree tree = load_tree_checked(tree_hash);

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

      it->hash = upsert_blob_to_tree(it->hash, dirs, depth + 1, blob_entry, touch_time, old_tree_hashes);
      it->flags |= 0x02;
      it->mtime = touch_time;
    }

    std::sort(tree.entries.begin(), tree.entries.end(), [](const Entry& a, const Entry& b) {
      return a.name < b.name;
    });

    return store_tree_object(tree);
  }

  std::array<uint8_t, 32> VaultEngine::remove_blob_from_tree(const std::array<uint8_t, 32>& tree_hash,
                                                const std::vector<std::string>& dirs,
                                                size_t depth,
                                                const std::string& blob_name,
                                                uint64_t touch_time,
                                                std::vector<std::array<uint8_t, 32>>& old_tree_hashes) {
    old_tree_hashes.push_back(tree_hash);
    Tree tree = load_tree_checked(tree_hash);

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

      it->hash = remove_blob_from_tree(it->hash, dirs, depth + 1, blob_name, touch_time, old_tree_hashes);
      it->flags |= 0x02;
      it->mtime = touch_time;
    }

    std::sort(tree.entries.begin(), tree.entries.end(), [](const Entry& a, const Entry& b) {
      return a.name < b.name;
    });

    return store_tree_object(tree);
  }
