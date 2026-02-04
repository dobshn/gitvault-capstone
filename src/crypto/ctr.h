#pragma once

#include <cstddef>

#include <openssl/evp.h>

#include "util.h"

class Aes256CtrStream {
 public:
  Aes256CtrStream(const ByteVec& key, const ByteVec& iv);
  ~Aes256CtrStream();

  Aes256CtrStream(const Aes256CtrStream&) = delete;
  Aes256CtrStream& operator=(const Aes256CtrStream&) = delete;

  void crypt(const uint8_t* input, size_t len, uint8_t* output);

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;
};

ByteVec aes256_ctr_crypt(const ByteVec& key, const ByteVec& iv, const ByteVec& input);
