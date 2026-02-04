#include "crypto/pbkdf2.h"

#include <cmath>
#include <stdexcept>

#include "crypto/hmac.h"

ByteVec pbkdf2_hmac_sha256(const std::string& password,
                           const ByteVec& salt,
                           uint32_t iterations,
                           size_t dk_len) {
  if (iterations == 0) {
    throw std::runtime_error("pbkdf2 iterations must be > 0");
  }
  ByteVec pass_bytes(password.begin(), password.end());
  constexpr size_t hlen = 32;
  size_t blocks = static_cast<size_t>(std::ceil(static_cast<double>(dk_len) / hlen));
  ByteVec out;
  out.reserve(blocks * hlen);

  for (size_t i = 1; i <= blocks; ++i) {
    ByteVec salt_block = salt;
    uint8_t block_index[4];
    block_index[0] = static_cast<uint8_t>((i >> 24) & 0xFF);
    block_index[1] = static_cast<uint8_t>((i >> 16) & 0xFF);
    block_index[2] = static_cast<uint8_t>((i >> 8) & 0xFF);
    block_index[3] = static_cast<uint8_t>(i & 0xFF);
    append_bytes(salt_block, block_index, 4);

    auto u = hmac_sha256(pass_bytes, salt_block);
    std::array<uint8_t, 32> t = u;

    for (uint32_t j = 1; j < iterations; ++j) {
      ByteVec u_bytes(u.begin(), u.end());
      u = hmac_sha256(pass_bytes, u_bytes);
      for (size_t k = 0; k < t.size(); ++k) {
        t[k] ^= u[k];
      }
    }

    out.insert(out.end(), t.begin(), t.end());
  }

  out.resize(dk_len);
  return out;
}
