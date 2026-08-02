#pragma once
#include <array>
#include <vector>
#include <cstdint>

using ByteVec = std::vector<uint8_t>;

struct Keys {
    ByteVec enc_key;
    ByteVec mac_key;
    ByteVec wrap_enc_key;
    ByteVec wrap_mac_key;
};

struct EncryptedObject {
    ByteVec data;
    std::array<uint8_t, 32> hash;
};

class ICrypto {
public:
    virtual ~ICrypto() = default;
    virtual EncryptedObject encrypt_object(const ByteVec& enc_key,
                                  const ByteVec& plaintext) = 0;

    virtual ByteVec decrypt_object_checked(const ByteVec& enc_key,
                          const ByteVec& data,
                          const std::array<uint8_t, 32>& expected_hash) = 0;

    virtual Keys derive_keys(const std::vector<uint8_t>& salt,
                    uint32_t iterations,
                    const std::string& password) = 0;
};
