#include "util.h"

#include <algorithm>
#include <iostream>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>

void print_usage() {
    std::cout << "gitvault <command> [args] [--password <pw>]\n";
    std::cout << "\nCommands:\n";
    std::cout << "  init <vault_name> [folder_path] (Initialize a vault and optionally upload a folder)\n";
    std::cout << "  add <vault_name> <local_path> <cloud_path>\n";
    std::cout << "  remove <vault_name> <cloud_path>\n";
    std::cout << "  mkdir <vault_name> <cloud_dir_path>\n";
    std::cout << "  rmdir <vault_name> <cloud_dir_path>\n";
    std::cout << "  list <vault_name> [path]\n";
    std::cout << "  tree <vault_name> [path]\n";
    std::cout << "  cat <vault_name> <path>\n";
    std::cout << "  quick-scan <vault_name>\n";
    std::cout << "  deep-scan <vault_name>\n";
    std::cout << "\nvault_name can be my_vault or /my_vault.\n";
}

std::string getHomeDirectory() {
#if defined(_WIN32) || defined(_WIN64)
  const char* home = std::getenv("USERPROFILE");
#else
  const char* home = std::getenv("HOME");
#endif
  if (!home) {
    throw std::runtime_error("Cannot determine home directory");
  }
  return std::string(home);
}

ByteVec read_file_bytes(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("failed to open file for reading: " + path.string());
  }
  file.seekg(0, std::ios::end);
  std::streamsize size = file.tellg();
  if (size < 0) {
    throw std::runtime_error("failed to read file size: " + path.string());
  }
  file.seekg(0, std::ios::beg);
  ByteVec buffer(static_cast<size_t>(size));
  if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    throw std::runtime_error("failed to read file: " + path.string());
  }
  return buffer;
}

void write_file_bytes(const std::filesystem::path& path, const ByteVec& data) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    throw std::runtime_error("failed to open file for writing: " + path.string());
  }
  if (!data.empty()) {
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  if (!file) {
    throw std::runtime_error("failed to write file: " + path.string());
  }
}

std::string to_hex(const ByteVec& data) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t b : data) {
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::string to_hex(const std::array<uint8_t, 32>& data) {
  ByteVec tmp(data.begin(), data.end());
  return to_hex(tmp);
}

static uint8_t hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<uint8_t>(10 + (c - 'a'));
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<uint8_t>(10 + (c - 'A'));
  }
  throw std::runtime_error("invalid hex character");
}

ByteVec from_hex(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("hex string length must be even");
  }
  ByteVec out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t high = hex_value(hex[i]);
    uint8_t low = hex_value(hex[i + 1]);
    out.push_back(static_cast<uint8_t>((high << 4) | low));
  }
  return out;
}

std::array<uint8_t, 32> hash_from_hex(const std::string& hex) {
  ByteVec bytes = from_hex(hex);
  if (bytes.size() != 32) {
    throw std::runtime_error("hash must be 32 bytes");
  }
  std::array<uint8_t, 32> out{};
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

ByteVec random_bytes(size_t len) {
  std::random_device rd;
  ByteVec out(len);
  for (size_t i = 0; i < len; ++i) {
    out[i] = static_cast<uint8_t>(rd());
  }
  return out;
}

void append_bytes(ByteVec& out, const uint8_t* data, size_t len) {
  out.insert(out.end(), data, data + len);
}

void write_u8(ByteVec& out, uint8_t v) {
  out.push_back(v);
}

void write_u16_be(ByteVec& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void write_u32_be(ByteVec& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void write_u64_be(ByteVec& out, uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
  }
}

uint8_t read_u8(const ByteVec& data, size_t& offset) {
  if (offset + 1 > data.size()) {
    throw std::runtime_error("buffer underflow");
  }
  uint8_t v = data[offset];
  offset += 1;
  return v;
}

uint16_t read_u16_be(const ByteVec& data, size_t& offset) {
  if (offset + 2 > data.size()) {
    throw std::runtime_error("buffer underflow");
  }
  uint16_t v = static_cast<uint16_t>(data[offset] << 8 | data[offset + 1]);
  offset += 2;
  return v;
}

uint32_t read_u32_be(const ByteVec& data, size_t& offset) {
  if (offset + 4 > data.size()) {
    throw std::runtime_error("buffer underflow");
  }
  uint32_t v = (static_cast<uint32_t>(data[offset]) << 24) |
               (static_cast<uint32_t>(data[offset + 1]) << 16) |
               (static_cast<uint32_t>(data[offset + 2]) << 8) |
               static_cast<uint32_t>(data[offset + 3]);
  offset += 4;
  return v;
}

uint64_t read_u64_be(const ByteVec& data, size_t& offset) {
  if (offset + 8 > data.size()) {
    throw std::runtime_error("buffer underflow");
  }
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | data[offset + i];
  }
  offset += 8;
  return v;
}

bool constant_time_equal(const ByteVec& a, const ByteVec& b) {
  if (a.size() != b.size()) {
    return false;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

bool constant_time_equal(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

uint64_t file_mtime_seconds(const std::filesystem::path& path) {
  auto ftime = std::filesystem::last_write_time(path);
  auto sys_time = std::chrono::time_point_cast<std::chrono::seconds>(
      ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
  return static_cast<uint64_t>(sys_time.time_since_epoch().count());
}

std::vector<std::string> split_path(const std::string& path) {
  std::vector<std::string> parts;
  std::stringstream ss(path);
  std::string item;
  while (std::getline(ss, item, '/')) {
    if (!item.empty()) {
      parts.push_back(item);
    }
  }
  return parts;
}

bool is_descendant_path(const std::filesystem::path& base, const std::filesystem::path& target) {
  std::error_code ec;
  std::filesystem::path canon_base = std::filesystem::weakly_canonical(base, ec);
  if (ec) {
    canon_base = std::filesystem::absolute(base);
  }
  ec.clear();
  std::filesystem::path canon_target = std::filesystem::weakly_canonical(target, ec);
  if (ec) {
    canon_target = std::filesystem::absolute(target);
  }

  auto base_it = canon_base.begin();
  auto target_it = canon_target.begin();
  for (; base_it != canon_base.end(); ++base_it, ++target_it) {
    if (target_it == canon_target.end() || *base_it != *target_it) {
      return false;
    }
  }
  return true;
}
