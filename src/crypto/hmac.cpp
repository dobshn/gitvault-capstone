#include "crypto/hmac.h"

std::array<uint8_t, 32> hmac_sha256(const ByteVec& key, const ByteVec& data) {
  constexpr size_t kBlockSize = 64;
  ByteVec key_block;
  if (key.size() > kBlockSize) {
    auto hashed = Sha256::hash(key);
    key_block.assign(hashed.begin(), hashed.end());
  } else {
    key_block = key;
  }
  key_block.resize(kBlockSize, 0x00);

  ByteVec o_key_pad(kBlockSize);
  ByteVec i_key_pad(kBlockSize);
  for (size_t i = 0; i < kBlockSize; ++i) {
    o_key_pad[i] = static_cast<uint8_t>(key_block[i] ^ 0x5c);
    i_key_pad[i] = static_cast<uint8_t>(key_block[i] ^ 0x36);
  }

  Sha256 inner;
  inner.update(i_key_pad);
  inner.update(data);
  auto inner_hash = inner.finalize();

  Sha256 outer;
  outer.update(o_key_pad);
  ByteVec inner_bytes(inner_hash.begin(), inner_hash.end());
  outer.update(inner_bytes);
  return outer.finalize();
}
