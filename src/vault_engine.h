#pragma once
#include <filesystem>
#include "format.h"
#include "object_store.h"
#include "crypto/CryptoImpl.h"
#include "crypto/ICrypto.h"
#include "vault_identity.h"
#include "thread_pool.h"
#include "anchor_event.h"
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>

struct ScanStats {
  size_t commits_checked = 0;
  size_t trees_checked = 0;
  size_t blobs_checked = 0;
  size_t blobs_missing = 0;
  size_t blobs_hashed = 0;
  size_t errors = 0;
};

struct PreparedVaultWrite {
    AnchorOperationId operation_id{};
    AnchorHash previous_head{};
    AnchorHash new_head{};
    ByteVec encrypted_head_bytes;
};

struct PathResult {
  bool is_directory = false;
  Tree tree;
  Entry entry;
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

class VaultEngine {
public:
    VaultEngine(ObjectStore& s, std::string password, bool creating_vault = false);
    ~VaultEngine() = default;
    std::array<uint8_t, 32> init_vault();
    std::array<uint8_t, 32> lock_vault(const std::filesystem::path& plain_dir);
    Tree list_directory(const std::string& path);
    Entry resolve_entry(const std::string& path, bool require_directory);
    ByteVec read_file_from_vault(const std::string& path);
    ScanStats quick_scan();
    ScanStats deep_scan();
    void print_tree(const std::string& path, std::ostream& out);
    PreparedVaultWrite prepare_add(const std::filesystem::path& local_path,
                                   const std::string& cloud_path,
                                   const AnchorHash& base_head);
    PreparedVaultWrite prepare_mkdir(const std::string& cloud_dir_path,
                                     const AnchorHash& base_head);
    PreparedVaultWrite prepare_remove(const std::string& cloud_path,
                                      const AnchorHash& base_head);
    PreparedVaultWrite prepare_rmdir(const std::string& cloud_dir_path,
                                     bool recursive,
                                     const AnchorHash& base_head);
    ByteVec encrypt_head(const AnchorHash& commit_hash) const;
    AnchorHash decrypt_head(const ByteVec& data) const;
    bool verify_commit_parent(const AnchorHash& commit_hash,
                              const AnchorHash& expected_parent_hash);
    bool is_commit_ancestor(const AnchorHash& ancestor,
                            const AnchorHash& descendant);
    const VaultIdentity& identity() const;
    const ByteVec& trust_mac_key() const;

private:
    ObjectStore& store;
    std::unique_ptr<ICrypto> crypto;
    Keys keys;
    Config cfg;
    std::optional<VaultIdentity> vault_identity;
    ThreadPool pool;
    std::mutex upload_mutex;
    std::vector<std::future<void>> pending_uploads;
    std::atomic<uint64_t> total_uploads;
    std::atomic<uint64_t> finished_uploads;
    std::mutex upload_progress_mutex;

    Config ensure_store_config(ObjectStore& store, bool creating_vault);
    void initialize_vault_identity();
    uint64_t unix_time_seconds();
    void log_progress_line(const std::filesystem::path& path, uint64_t processed, uint64_t total, const std::chrono::steady_clock::time_point& start);
    void write_head(const std::array<uint8_t, 32>& commit_hash);
    std::array<uint8_t, 32> read_head();
    PreparedVaultWrite make_prepared_write(const AnchorHash& previous_head,
                                           const AnchorHash& new_head) const;
    std::array<uint8_t, 32> store_commit(const std::array<uint8_t, 32>& root_hash,
                                        uint64_t commit_time,
                                        const std::array<uint8_t, 32>& parent_hash);
    std::array<uint8_t, 32> store_commit_object(
        const std::array<uint8_t, 32>& root_hash,
        uint64_t commit_time,
        const std::array<uint8_t, 32>& parent_hash);
    std::array<uint8_t, 32> store_tree_object(const Tree& tree);
    Commit load_commit_checked(const std::array<uint8_t, 32>& commit_hash);
    Commit load_commit_history_checked(const std::array<uint8_t, 32>& head_hash,
                                       size_t& commits_checked);
    Tree load_tree_checked(const std::array<uint8_t, 32>& tree_hash);
    std::array<uint8_t, 32> store_blob(const std::filesystem::path& path);
    std::array<uint8_t, 32> store_tree(const std::filesystem::path& dir);
    PathResult resolve_path(const std::string& path);
    PathResult resolve_path_at(const AnchorHash& head_hash,
                               const std::string& path);
    Entry resolve_entry_at(const AnchorHash& head_hash,
                           const std::string& path,
                           bool require_directory);
    void scan_tree(const std::array<uint8_t, 32>& tree_hash,
                   const std::string& line,
                   const std::string& child_prefix,
                   bool deep,
                   ScanStats& stats,
                   std::ostream& out);
    void collect_subtree_hashes(const std::array<uint8_t, 32>& tree_hash,
                                std::vector<std::array<uint8_t, 32>>& tree_hashes,
                                std::vector<std::array<uint8_t, 32>>& blob_hashes);
    void print_tree_recursive(const Tree& tree, const std::string& prefix, std::ostream& out);
    std::array<uint8_t, 32> upsert_dir_to_tree(const std::array<uint8_t, 32>& tree_hash,
                                              const std::vector<std::string>& dirs,
                                              size_t depth,
                                              const Entry& dir_entry,
                                              uint64_t touch_time,
                                              std::vector<std::array<uint8_t, 32>>& old_tree_hashes);
    std::array<uint8_t, 32> upsert_blob_to_tree(const std::array<uint8_t, 32>& tree_hash,
                                              const std::vector<std::string>& dirs,
                                              size_t depth,
                                              const Entry& blob_entry,
                                              uint64_t touch_time,
                                              std::vector<std::array<uint8_t, 32>>& old_tree_hashes);
    std::array<uint8_t, 32> remove_dir_from_tree(const std::array<uint8_t, 32>& tree_hash,
                                                const std::vector<std::string>& dirs,
                                                size_t depth,
                                                const std::string& dir_name,
                                                uint64_t touch_time,
                                                bool recursive,
                                                std::vector<std::array<uint8_t, 32>>& old_tree_hashes,
                                                std::vector<std::array<uint8_t, 32>>& removed_tree_hashes,
                                                std::vector<std::array<uint8_t, 32>>& removed_blob_hashes);
    std::array<uint8_t, 32> remove_blob_from_tree(const std::array<uint8_t, 32>& tree_hash,
                                                const std::vector<std::string>& dirs,
                                                size_t depth,
                                                const std::string& blob_name,
                                                uint64_t touch_time,
                                                std::vector<std::array<uint8_t, 32>>& old_tree_hashes);
    void wait_for_uploads();
};
