#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "util.h"

class Sha256 {
 public:
  Sha256();

  void update(const uint8_t* data, size_t len);
  void update(const ByteVec& data);
  std::array<uint8_t, 32> finalize();

  static std::array<uint8_t, 32> hash(const ByteVec& data);

 private:
  void transform(const uint8_t block[64]);

  uint32_t state_[8];
  uint64_t bitlen_;
  uint8_t buffer_[64];
  size_t buffer_len_;
};
