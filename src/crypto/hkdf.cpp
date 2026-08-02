#include "crypto/hkdf.h"

#include <algorithm>
#include <stdexcept>

#include "crypto/hmac.h"

ByteVec hkdf_extract_sha256(const ByteVec& input_key_material,
                            const ByteVec& salt) {
  constexpr size_t kHashLength = 32;
  const ByteVec extract_salt = salt.empty() ? ByteVec(kHashLength, 0) : salt;
  const auto pseudorandom_key_array = hmac_sha256(extract_salt, input_key_material);
  return ByteVec(pseudorandom_key_array.begin(), pseudorandom_key_array.end());
}

ByteVec hkdf_expand_sha256(const ByteVec& pseudorandom_key,
                           const ByteVec& info,
                           size_t output_length) {
  constexpr size_t kHashLength = 32;
  constexpr size_t kMaxOutputLength = 255 * kHashLength;
  if (pseudorandom_key.size() != kHashLength) {
    throw std::runtime_error("HKDF pseudorandom key must be 32 bytes");
  }
  if (output_length > kMaxOutputLength) {
    throw std::runtime_error("HKDF output length is too large");
  }

  ByteVec output;
  output.reserve(output_length);
  ByteVec previous_block;
  for (uint16_t counter = 1; output.size() < output_length; ++counter) {
    ByteVec input;
    input.reserve(previous_block.size() + info.size() + 1);
    if (!previous_block.empty()) {
      append_bytes(input, previous_block.data(), previous_block.size());
    }
    if (!info.empty()) {
      append_bytes(input, info.data(), info.size());
    }
    write_u8(input, static_cast<uint8_t>(counter));

    const auto block_array = hmac_sha256(pseudorandom_key, input);
    previous_block.assign(block_array.begin(), block_array.end());
    const size_t remaining = output_length - output.size();
    output.insert(output.end(), previous_block.begin(),
                  previous_block.begin() + std::min(remaining, previous_block.size()));
  }
  return output;
}

ByteVec hkdf_sha256(const ByteVec& input_key_material,
                    const ByteVec& salt,
                    const ByteVec& info,
                    size_t output_length) {
  return hkdf_expand_sha256(hkdf_extract_sha256(input_key_material, salt),
                            info, output_length);
}
