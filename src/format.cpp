#include "format.h"

#include <algorithm>
#include <stdexcept>

ByteVec serialize_tree(const Tree& tree) {
  ByteVec out;
  write_u8(out, tree.version);
  if (tree.entries.size() > 0xFFFFFFFFu) {
    throw std::runtime_error("too many tree entries");
  }
  write_u32_be(out, static_cast<uint32_t>(tree.entries.size()));

  for (const auto& entry : tree.entries) {
    write_u8(out, entry.type);
    write_u8(out, entry.flags);
    if (entry.name.size() > 0xFFFF) {
      throw std::runtime_error("entry name too long");
    }
    write_u16_be(out, static_cast<uint16_t>(entry.name.size()));
    append_bytes(out, reinterpret_cast<const uint8_t*>(entry.name.data()), entry.name.size());
    append_bytes(out, entry.hash.data(), entry.hash.size());
    if (entry.flags & 0x01) {
      if (!entry.size.has_value()) {
        throw std::runtime_error("entry size flag set but size missing");
      }
      write_u64_be(out, entry.size.value());
    }
    if (entry.flags & 0x02) {
      if (!entry.mtime.has_value()) {
        throw std::runtime_error("entry mtime flag set but mtime missing");
      }
      write_u64_be(out, entry.mtime.value());
    }
  }
  return out;
}

Tree deserialize_tree(const ByteVec& data) {
  size_t offset = 0;
  Tree tree;
  tree.version = read_u8(data, offset);
  if (tree.version != 1) {
    throw std::runtime_error("unsupported tree version");
  }
  uint32_t count = read_u32_be(data, offset);
  tree.entries.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    Entry entry;
    entry.type = read_u8(data, offset);
    entry.flags = read_u8(data, offset);
    uint16_t name_len = read_u16_be(data, offset);
    if (offset + name_len > data.size()) {
      throw std::runtime_error("tree entry name out of bounds");
    }
    entry.name.assign(reinterpret_cast<const char*>(data.data() + offset), name_len);
    offset += name_len;
    if (offset + entry.hash.size() > data.size()) {
      throw std::runtime_error("tree entry hash out of bounds");
    }
    std::copy(data.begin() + offset, data.begin() + offset + entry.hash.size(), entry.hash.begin());
    offset += entry.hash.size();
    if (entry.flags & 0x01) {
      entry.size = read_u64_be(data, offset);
    }
    if (entry.flags & 0x02) {
      entry.mtime = read_u64_be(data, offset);
    }
    tree.entries.push_back(entry);
  }

  return tree;
}

ByteVec serialize_commit(const Commit& commit) {
  if (commit.version != 2) {
    throw std::runtime_error("unsupported commit version");
  }

  ByteVec out;
  write_u8(out, commit.version);
  write_u64_be(out, commit.commit_time);
  append_bytes(out, commit.root_hash.data(), commit.root_hash.size());
  append_bytes(out, commit.parent_hash.data(), commit.parent_hash.size());
  return out;
}

Commit deserialize_commit(const ByteVec& data) {
  constexpr size_t kCommitV2Size = 1 + 8 + 32 + 32;

  size_t offset = 0;
  Commit commit;
  commit.version = read_u8(data, offset);
  if (commit.version != 2) {
    throw std::runtime_error("unsupported commit version");
  }
  if (data.size() != kCommitV2Size) {
    throw std::runtime_error("invalid commit size for version 2");
  }

  commit.commit_time = read_u64_be(data, offset);
  std::copy(data.begin() + offset, data.begin() + offset + commit.root_hash.size(), commit.root_hash.begin());
  offset += commit.root_hash.size();
  std::copy(data.begin() + offset, data.begin() + offset + commit.parent_hash.size(),
            commit.parent_hash.begin());
  return commit;
}
