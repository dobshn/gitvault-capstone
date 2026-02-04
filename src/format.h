#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "util.h"

struct Entry {
  uint8_t type = 0;  // 0=blob, 1=tree
  uint8_t flags = 0;
  std::string name;
  std::array<uint8_t, 32> hash{};
  std::optional<uint64_t> size;
  std::optional<uint64_t> mtime;
};

struct Tree {
  uint8_t version = 1;
  std::vector<Entry> entries;
};

struct Commit {
  uint8_t version = 1;
  uint64_t commit_time = 0;
  std::array<uint8_t, 32> root_hash{};
};

ByteVec serialize_tree(const Tree& tree);
Tree deserialize_tree(const ByteVec& data);

ByteVec serialize_commit(const Commit& commit);
Commit deserialize_commit(const ByteVec& data);
