#include "crypto/nip44.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "util.h"

namespace {
int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    failures++;
  }
}

void expect_throw(const std::function<void()>& action,
                  const std::string& message) {
  try {
    action();
    std::cerr << "FAIL: " << message << " did not throw\n";
    failures++;
  } catch (const std::runtime_error&) {
  }
}

template <size_t N>
std::array<uint8_t, N> fixed(const std::string& hex) {
  const ByteVec bytes = from_hex(hex);
  if (bytes.size() != N) throw std::runtime_error("bad test vector");
  std::array<uint8_t, N> result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

void test_official_vector() {
  const auto sec1 = fixed<32>(
      "0000000000000000000000000000000000000000000000000000000000000001");
  const auto sec2 = fixed<32>(
      "0000000000000000000000000000000000000000000000000000000000000002");
  const auto expected_key = fixed<32>(
      "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
  const auto nonce = fixed<32>(
      "0000000000000000000000000000000000000000000000000000000000000001");
  const std::string expected_payload =
      "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";

  const auto key12 = nip44_conversation_key(sec1, schnorr_public_key(sec2));
  const auto key21 = nip44_conversation_key(sec2, schnorr_public_key(sec1));
  expect(key12 == expected_key && key21 == expected_key,
         "conversation key matches the official NIP-44 vector");
  const std::string payload = nip44_encrypt_with_nonce("a", key12, nonce);
  expect(payload == expected_payload,
         "encrypted payload matches the official NIP-44 vector");
  expect(nip44_decrypt(payload, key21) == "a",
         "official NIP-44 payload decrypts");
}

void test_self_encryption_and_rejection() {
  auto secret = fixed<32>(
      "0000000000000000000000000000000000000000000000000000000000000003");
  const auto key = nip44_conversation_key(secret, schnorr_public_key(secret));
  const std::string plaintext =
      "{\"event_type\":\"head_proposal\",\"message\":\"한글\"}";
  std::string payload = nip44_encrypt(plaintext, key);
  expect(nip44_decrypt(payload, key) == plaintext,
         "Vault key can encrypt and decrypt its own payload");

  payload[payload.size() / 2] = payload[payload.size() / 2] == 'A' ? 'B' : 'A';
  expect_throw([&] { (void)nip44_decrypt(payload, key); },
               "modified payload is rejected");
  expect_throw([&] { (void)nip44_encrypt("", key); },
               "empty plaintext is rejected");
  expect_throw([&] { (void)nip44_encrypt(std::string(16 * 1024 + 1, 'x'), key); },
               "oversized plaintext is rejected");
}
}  // namespace

int main() {
  test_official_vector();
  test_self_encryption_and_rejection();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all NIP-44 tests passed\n";
  return 0;
}
