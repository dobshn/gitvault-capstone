#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

using ByteVec = std::vector<uint8_t>;

ByteVec read_file_bytes(const std::filesystem::path& path);
void write_file_bytes(const std::filesystem::path& path, const ByteVec& data);

std::string to_hex(const ByteVec& data);
std::string to_hex(const std::array<uint8_t, 32>& data);
ByteVec from_hex(const std::string& hex);
std::array<uint8_t, 32> hash_from_hex(const std::string& hex);

ByteVec random_bytes(size_t len);

void append_bytes(ByteVec& out, const uint8_t* data, size_t len);
void write_u8(ByteVec& out, uint8_t v);
void write_u16_be(ByteVec& out, uint16_t v);
void write_u32_be(ByteVec& out, uint32_t v);
void write_u64_be(ByteVec& out, uint64_t v);

uint8_t read_u8(const ByteVec& data, size_t& offset);
uint16_t read_u16_be(const ByteVec& data, size_t& offset);
uint32_t read_u32_be(const ByteVec& data, size_t& offset);
uint64_t read_u64_be(const ByteVec& data, size_t& offset);

bool constant_time_equal(const ByteVec& a, const ByteVec& b);
bool constant_time_equal(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);

uint64_t file_mtime_seconds(const std::filesystem::path& path);

std::vector<std::string> split_path(const std::string& path);

bool is_descendant_path(const std::filesystem::path& base, const std::filesystem::path& target);
