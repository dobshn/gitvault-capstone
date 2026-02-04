#include "crypto/ctr.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace {
void check_ok(int result, const char* message) {
  if (result != 1) {
    throw std::runtime_error(message);
  }
}
}  // namespace

Aes256CtrStream::Aes256CtrStream(const ByteVec& key, const ByteVec& iv) {
  if (key.size() != 32) {
    throw std::runtime_error("AES-256 key must be 32 bytes");
  }
  if (iv.size() != 16) {
    throw std::runtime_error("AES-CTR IV must be 16 bytes");
  }
  ctx_ = EVP_CIPHER_CTX_new();
  if (!ctx_) {
    throw std::runtime_error("failed to allocate EVP_CIPHER_CTX");
  }
  check_ok(EVP_EncryptInit_ex(ctx_, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()),
           "EVP_EncryptInit_ex failed");
  check_ok(EVP_CIPHER_CTX_set_padding(ctx_, 0), "EVP_CIPHER_CTX_set_padding failed");
}

Aes256CtrStream::~Aes256CtrStream() {
  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
  }
}

void Aes256CtrStream::crypt(const uint8_t* input, size_t len, uint8_t* output) {
  size_t offset = 0;
  while (offset < len) {
    size_t chunk = std::min(len - offset, static_cast<size_t>(std::numeric_limits<int>::max()));
    int out_len = 0;
    check_ok(EVP_EncryptUpdate(ctx_,
                              output + offset,
                              &out_len,
                              input + offset,
                              static_cast<int>(chunk)),
             "EVP_EncryptUpdate failed");
    if (out_len != static_cast<int>(chunk)) {
      throw std::runtime_error("EVP_EncryptUpdate produced unexpected length");
    }
    offset += chunk;
  }
}

ByteVec aes256_ctr_crypt(const ByteVec& key, const ByteVec& iv, const ByteVec& input) {
  ByteVec output(input.size());
  Aes256CtrStream stream(key, iv);
  if (!input.empty()) {
    stream.crypt(input.data(), input.size(), output.data());
  }
  return output;
}
