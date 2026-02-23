#include "crypto/CryptoImpl.h"
#include "crypto/ctr.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "util.h"

namespace {
constexpr size_t kIvSize = 16;
}

EncryptedObject CryptoImpl::encrypt_object(const ByteVec& enc_key,
                                      const ByteVec& plaintext) {
    ByteVec iv = random_bytes(kIvSize);
    ByteVec ciphertext = aes256_ctr_crypt(enc_key, iv, plaintext);

    ByteVec combined;
    combined.insert(combined.end(), iv.begin(), iv.end());
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

    auto hash = Sha256::hash(combined);
    return {combined, hash};
}

ByteVec CryptoImpl::decrypt_object_checked(const ByteVec& enc_key,
                              const ByteVec& data,
                              const std::array<uint8_t, 32>& expected_hash) {
    auto actual_hash = Sha256::hash(data);
    if (!constant_time_equal(actual_hash, expected_hash)) {
        throw std::runtime_error("object hash mismatch");
    }
    if (data.size() < kIvSize) {
    throw std::runtime_error("object too small: " + to_hex(expected_hash));
  }

    ByteVec iv(data.begin(), data.begin() + kIvSize);
    ByteVec ciphertext(data.begin() + kIvSize, data.end());

    return aes256_ctr_crypt(enc_key, iv, ciphertext);
}

Keys CryptoImpl::derive_keys(const std::vector<uint8_t>& salt,
                        uint32_t iterations,
                        const std::string& password) {
    ByteVec key_material =
        pbkdf2_hmac_sha256(password, salt, iterations, 64);

    Keys keys;
    keys.enc_key.assign(key_material.begin(), key_material.begin() + 32);
    keys.mac_key.assign(key_material.begin() + 32, key_material.end());
    return keys;
}