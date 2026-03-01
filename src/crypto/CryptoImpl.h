#pragma once
#include <array>
#include <vector>
#include <string>
#include "crypto/ICrypto.h"
#include "crypto/sha256.h"

using ByteVec = std::vector<uint8_t>;

class CryptoImpl : public ICrypto {
public:
    EncryptedObject encrypt_object(const ByteVec& enc_key,
                                  const ByteVec& plaintext) override;

    ByteVec decrypt_object_checked(const ByteVec& enc_key,
                          const ByteVec& data,
                          const std::array<uint8_t, 32>& expected_hash) override;

    Keys derive_keys(const std::vector<uint8_t>& salt,
                    uint32_t iterations,
                    const std::string& password) override;
};