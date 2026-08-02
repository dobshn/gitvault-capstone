#include "crypto/CryptoImpl.h"
#include "crypto/ctr.h"
#include "crypto/hkdf.h"
#include "crypto/pbkdf2.h"
#include "util.h"

#include <string_view>

namespace {
    constexpr size_t kIvSize = 16;

    ByteVec to_bytes(std::string_view text) {
      return ByteVec(text.begin(), text.end());
    }

    ByteVec derive_subkey(const ByteVec& master_key, std::string_view label) {
      return hkdf_sha256(master_key,
                         to_bytes("gitvault/key-schedule/v2"),
                         to_bytes(label),
                         32);
    }
}

EncryptedObject CryptoImpl::encrypt_object(const ByteVec& enc_key,
                                      const ByteVec& plaintext) {
    ByteVec iv = random_bytes(kIvSize);
    ByteVec ciphertext = aes256_ctr_crypt(enc_key, iv, plaintext);
    ByteVec combined;
    combined.reserve(iv.size() + ciphertext.size());
    append_bytes(combined, iv.data(), iv.size());
    append_bytes(combined, ciphertext.data(), ciphertext.size());
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
    ByteVec master_key =
        pbkdf2_hmac_sha256(password, salt, iterations, 32);

    Keys keys;
    keys.enc_key = derive_subkey(master_key, "gitvault/object-enc/v2");
    keys.mac_key = derive_subkey(master_key, "gitvault/head-mac/v2");
    keys.wrap_enc_key = derive_subkey(master_key, "gitvault/identity-wrap-enc/v2");
    keys.wrap_mac_key = derive_subkey(master_key, "gitvault/identity-wrap-mac/v2");
    return keys;
}
