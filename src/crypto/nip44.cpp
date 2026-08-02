#include "crypto/nip44.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>

#include "crypto/hkdf.h"
#include "crypto/hmac.h"
#include "util.h"

namespace {
constexpr size_t kNonceSize = 32;
constexpr size_t kMacSize = 32;
constexpr size_t kMetadataSize = 1 + kNonceSize + kMacSize;
constexpr size_t kMaxPlaintextSize = 16 * 1024;

struct MessageKeys {
  ByteVec chacha_key;
  ByteVec chacha_nonce;
  ByteVec hmac_key;
};

size_t padded_length(size_t unpadded_length) {
  if (unpadded_length == 0 || unpadded_length > kMaxPlaintextSize) {
    throw std::runtime_error("NIP-44 plaintext size is out of range");
  }
  if (unpadded_length <= 32) {
    return 32;
  }
  size_t next_power = 1;
  while (next_power < unpadded_length) {
    if (next_power > std::numeric_limits<size_t>::max() / 2) {
      throw std::runtime_error("NIP-44 padding size overflow");
    }
    next_power *= 2;
  }
  const size_t chunk = next_power <= 256 ? 32 : next_power / 8;
  return chunk * ((unpadded_length - 1) / chunk + 1);
}

ByteVec pad(const std::string& plaintext) {
  const size_t length = plaintext.size();
  if (length == 0 || length >= 65536 || length > kMaxPlaintextSize) {
    throw std::runtime_error("NIP-44 plaintext size is out of range");
  }
  ByteVec output;
  output.reserve(2 + padded_length(length));
  write_u16_be(output, static_cast<uint16_t>(length));
  output.insert(output.end(), plaintext.begin(), plaintext.end());
  output.resize(2 + padded_length(length), 0);
  return output;
}

std::string unpad(const ByteVec& padded) {
  if (padded.size() < 34) {
    throw std::runtime_error("invalid NIP-44 padded plaintext");
  }
  size_t offset = 0;
  const size_t length = read_u16_be(padded, offset);
  if (length == 0 || length > kMaxPlaintextSize ||
      padded.size() != 2 + padded_length(length)) {
    throw std::runtime_error("invalid NIP-44 padding");
  }
  if (!std::all_of(padded.begin() + 2 + length, padded.end(),
                   [](uint8_t byte) { return byte == 0; })) {
    throw std::runtime_error("invalid NIP-44 padding bytes");
  }
  return std::string(padded.begin() + 2, padded.begin() + 2 + length);
}

MessageKeys message_keys(const Nip44ConversationKey& conversation_key,
                         const std::array<uint8_t, 32>& nonce) {
  const ByteVec key(conversation_key.begin(), conversation_key.end());
  const ByteVec info(nonce.begin(), nonce.end());
  const ByteVec expanded = hkdf_expand_sha256(key, info, 76);
  return {ByteVec(expanded.begin(), expanded.begin() + 32),
          ByteVec(expanded.begin() + 32, expanded.begin() + 44),
          ByteVec(expanded.begin() + 44, expanded.end())};
}

ByteVec chacha20(const ByteVec& key,
                 const ByteVec& nonce,
                 const ByteVec& input) {
  if (key.size() != 32 || nonce.size() != 12 ||
      input.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error("invalid NIP-44 ChaCha20 parameters");
  }
  std::array<uint8_t, 16> iv{};
  std::copy(nonce.begin(), nonce.end(), iv.begin() + 4);
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
      EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_EncryptInit_ex(context.get(), EVP_chacha20(), nullptr, key.data(),
                         iv.data()) != 1) {
    throw std::runtime_error("failed to initialize NIP-44 ChaCha20");
  }
  ByteVec output(input.size() + EVP_CIPHER_block_size(EVP_chacha20()));
  int written = 0;
  int final_written = 0;
  if (EVP_EncryptUpdate(context.get(), output.data(), &written, input.data(),
                        static_cast<int>(input.size())) != 1 ||
      EVP_EncryptFinal_ex(context.get(), output.data() + written,
                          &final_written) != 1) {
    throw std::runtime_error("NIP-44 ChaCha20 operation failed");
  }
  output.resize(static_cast<size_t>(written + final_written));
  return output;
}

std::string base64_encode(const ByteVec& input) {
  if (input.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error("NIP-44 payload is too large");
  }
  std::string output(4 * ((input.size() + 2) / 3), '\0');
  const int written = EVP_EncodeBlock(
      reinterpret_cast<unsigned char*>(&output[0]), input.data(),
      static_cast<int>(input.size()));
  if (written < 0 || static_cast<size_t>(written) != output.size()) {
    throw std::runtime_error("NIP-44 base64 encoding failed");
  }
  return output;
}

ByteVec base64_decode(const std::string& input) {
  if (input.size() < 132 || input.size() % 4 != 0 ||
      input.size() > 4 * ((kMaxPlaintextSize + kMetadataSize + 4) / 3 + 1)) {
    throw std::runtime_error("invalid NIP-44 payload size");
  }
  ByteVec output(input.size() / 4 * 3);
  const int written = EVP_DecodeBlock(
      output.data(), reinterpret_cast<const unsigned char*>(input.data()),
      static_cast<int>(input.size()));
  if (written < 0) {
    throw std::runtime_error("invalid NIP-44 base64 payload");
  }
  size_t padding = 0;
  if (!input.empty() && input.back() == '=') padding++;
  if (input.size() > 1 && input[input.size() - 2] == '=') padding++;
  if (static_cast<size_t>(written) < padding) {
    throw std::runtime_error("invalid NIP-44 base64 padding");
  }
  output.resize(static_cast<size_t>(written) - padding);
  if (base64_encode(output) != input) {
    throw std::runtime_error("non-canonical NIP-44 base64 payload");
  }
  return output;
}
}  // namespace

Nip44ConversationKey nip44_conversation_key(
    const std::array<uint8_t, 32>& private_key,
    const SchnorrPublicKey& public_key) {
  const auto shared = secp256k1_shared_x(private_key, public_key);
  const ByteVec extracted = hkdf_extract_sha256(
      ByteVec(shared.begin(), shared.end()),
      ByteVec{'n', 'i', 'p', '4', '4', '-', 'v', '2'});
  Nip44ConversationKey result{};
  std::copy(extracted.begin(), extracted.end(), result.begin());
  return result;
}

std::string nip44_encrypt(
    const std::string& plaintext,
    const Nip44ConversationKey& conversation_key) {
  const ByteVec random_nonce = random_bytes(kNonceSize);
  std::array<uint8_t, 32> nonce{};
  std::copy(random_nonce.begin(), random_nonce.end(), nonce.begin());
  return nip44_encrypt_with_nonce(plaintext, conversation_key, nonce);
}

std::string nip44_encrypt_with_nonce(
    const std::string& plaintext,
    const Nip44ConversationKey& conversation_key,
    const std::array<uint8_t, 32>& nonce) {
  const MessageKeys keys = message_keys(conversation_key, nonce);
  const ByteVec ciphertext = chacha20(keys.chacha_key, keys.chacha_nonce,
                                      pad(plaintext));
  ByteVec authenticated(nonce.begin(), nonce.end());
  authenticated.insert(authenticated.end(), ciphertext.begin(), ciphertext.end());
  const auto mac = hmac_sha256(keys.hmac_key, authenticated);

  ByteVec output;
  output.reserve(kMetadataSize + ciphertext.size());
  output.push_back(2);
  output.insert(output.end(), nonce.begin(), nonce.end());
  output.insert(output.end(), ciphertext.begin(), ciphertext.end());
  output.insert(output.end(), mac.begin(), mac.end());
  return base64_encode(output);
}

std::string nip44_decrypt(
    const std::string& payload,
    const Nip44ConversationKey& conversation_key) {
  if (!payload.empty() && payload.front() == '#') {
    throw std::runtime_error("unsupported NIP-44 encoding version");
  }
  const ByteVec decoded = base64_decode(payload);
  if (decoded.size() < 99 || decoded.front() != 2) {
    throw std::runtime_error("unsupported or invalid NIP-44 payload version");
  }
  std::array<uint8_t, 32> nonce{};
  std::copy(decoded.begin() + 1, decoded.begin() + 33, nonce.begin());
  const ByteVec ciphertext(decoded.begin() + 33,
                           decoded.end() - static_cast<ptrdiff_t>(kMacSize));
  const ByteVec actual_mac(decoded.end() - static_cast<ptrdiff_t>(kMacSize),
                           decoded.end());
  const MessageKeys keys = message_keys(conversation_key, nonce);
  ByteVec authenticated(nonce.begin(), nonce.end());
  authenticated.insert(authenticated.end(), ciphertext.begin(), ciphertext.end());
  const auto expected_array = hmac_sha256(keys.hmac_key, authenticated);
  const ByteVec expected(expected_array.begin(), expected_array.end());
  if (!constant_time_equal(actual_mac, expected)) {
    throw std::runtime_error("NIP-44 payload authentication failed");
  }
  return unpad(chacha20(keys.chacha_key, keys.chacha_nonce, ciphertext));
}
