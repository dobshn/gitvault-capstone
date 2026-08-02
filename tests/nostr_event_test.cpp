#include "crypto/schnorr.h"
#include "nostr_event.h"
#include "util.h"

#include <algorithm>
#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    failures++;
  }
}

void expect_throw(const std::function<void()>& action,
                  const std::string& expected_message,
                  const std::string& test_name) {
  try {
    action();
    std::cerr << "FAIL: " << test_name << " did not throw\n";
    failures++;
  } catch (const std::runtime_error& error) {
    if (std::string(error.what()).find(expected_message) == std::string::npos) {
      std::cerr << "FAIL: " << test_name
                << " threw unexpected error: " << error.what() << "\n";
      failures++;
    }
  }
}

template <size_t N>
std::array<uint8_t, N> fixed_bytes(const std::string& encoded) {
  const ByteVec bytes = from_hex(encoded);
  if (bytes.size() != N) {
    throw std::runtime_error("unexpected test vector length");
  }
  std::array<uint8_t, N> result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

void test_bip340_official_vector_zero() {
  const auto secret = fixed_bytes<32>(
      "0000000000000000000000000000000000000000000000000000000000000003");
  const auto public_key = fixed_bytes<32>(
      "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
  const auto message = fixed_bytes<32>(
      "0000000000000000000000000000000000000000000000000000000000000000");
  const auto auxiliary_randomness = fixed_bytes<32>(
      "0000000000000000000000000000000000000000000000000000000000000000");
  const auto expected_signature = fixed_bytes<64>(
      "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
      "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0");

  expect(schnorr_public_key(secret) == public_key,
         "BIP-340 vector 0 public key matches");
  const auto signature =
      schnorr_sign_digest(secret, message, auxiliary_randomness);
  expect(signature == expected_signature,
         "BIP-340 vector 0 signature matches");
  expect(schnorr_verify_digest(public_key, message, signature),
         "BIP-340 vector 0 verifies");

  auto tampered_signature = signature;
  tampered_signature.back() ^= 0x01;
  expect(!schnorr_verify_digest(public_key, message, tampered_signature),
         "a modified BIP-340 signature is rejected");
}

UnsignedNostrEvent sample_event() {
  UnsignedNostrEvent event;
  event.created_at = 123456789;
  event.kind = 9500;
  event.tags = {{"x", "line\nvalue"}, {"unicode", "한글"}};
  event.content = "quote\" slash\\ newline\n tab\t 한글";
  return event;
}

void test_nip01_canonical_serialization_and_id() {
  const auto public_key = fixed_bytes<32>(
      "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
  const std::string expected =
      "[0,\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\","
      "123456789,9500,[[\"x\",\"line\\nvalue\"],[\"unicode\",\"한글\"]],"
      "\"quote\\\" slash\\\\ newline\\n tab\\t 한글\"]";

  expect(serialize_nostr_event_canonical(public_key, sample_event()) == expected,
         "canonical event bytes match the NIP-01 array form exactly");
  expect(compute_nostr_event_id(public_key, sample_event()) ==
             fixed_bytes<32>(
                 "83b11e8fa6ed32ad5f77ab87180ce97ced3fb7c74fbe78adb2be2b48abf9954b"),
         "event ID is SHA-256 of the exact UTF-8 canonical bytes");
}

void test_event_signing_and_tamper_detection() {
  const auto secret = fixed_bytes<32>(
      "0000000000000000000000000000000000000000000000000000000000000003");
  const SignedNostrEvent event = sign_nostr_event(sample_event(), secret);
  const SchnorrPublicKey trusted_public_key = schnorr_public_key(secret);

  expect(event.public_key == trusted_public_key,
         "event carries the signing key's x-only public key");
  expect(verify_nostr_event(event, trusted_public_key),
         "a newly signed event verifies against the trusted Vault key");

  SignedNostrEvent changed_content = event;
  changed_content.content += "!";
  expect(!verify_nostr_event(changed_content, trusted_public_key),
         "changed content is rejected");

  SignedNostrEvent changed_tag = event;
  changed_tag.tags[0][1] = "different";
  expect(!verify_nostr_event(changed_tag, trusted_public_key),
         "changed tags are rejected");

  SignedNostrEvent changed_id = event;
  changed_id.id[0] ^= 0x01;
  expect(!verify_nostr_event(changed_id, trusted_public_key),
         "changed event ID is rejected");

  SignedNostrEvent changed_signature = event;
  changed_signature.signature[0] ^= 0x01;
  expect(!verify_nostr_event(changed_signature, trusted_public_key),
         "changed event signature is rejected");

  auto other_secret = secret;
  other_secret.back() = 4;
  const SignedNostrEvent self_signed_by_attacker =
      sign_nostr_event(sample_event(), other_secret);
  expect(!verify_nostr_event(self_signed_by_attacker, trusted_public_key),
         "a valid event signed by an untrusted key is rejected");
}

void test_wire_json_round_trip_and_strict_parsing() {
  const auto secret = fixed_bytes<32>(
      "0000000000000000000000000000000000000000000000000000000000000003");
  const SignedNostrEvent original = sign_nostr_event(sample_event(), secret);
  const SchnorrPublicKey trusted_public_key = schnorr_public_key(secret);
  const std::string encoded = serialize_nostr_event_json(original);
  const SignedNostrEvent decoded = deserialize_nostr_event_json(encoded);

  expect(decoded.id == original.id &&
             decoded.public_key == original.public_key &&
             decoded.created_at == original.created_at &&
             decoded.kind == original.kind && decoded.tags == original.tags &&
             decoded.content == original.content &&
             decoded.signature == original.signature,
         "wire JSON round-trips every NIP-01 event field");
  expect(verify_nostr_event(decoded, trusted_public_key),
         "round-tripped event verifies");

  std::string uppercase_public_key = encoded;
  const std::string public_key_hex = to_hex(original.public_key);
  const size_t public_key_position = uppercase_public_key.find(public_key_hex);
  uppercase_public_key[public_key_position] = 'F';
  expect_throw(
      [&] { (void)deserialize_nostr_event_json(uppercase_public_key); },
      "lowercase hex", "uppercase public key");

  std::string short_id = encoded;
  const std::string id_hex = to_hex(original.id);
  const size_t id_position = short_id.find(id_hex);
  short_id.erase(id_position, 1);
  expect_throw([&] { (void)deserialize_nostr_event_json(short_id); },
               "lowercase hex", "short event ID");

  std::string negative_timestamp = encoded;
  const std::string timestamp = "\"created_at\":123456789";
  const size_t timestamp_position = negative_timestamp.find(timestamp);
  negative_timestamp.replace(timestamp_position, timestamp.size(),
                             "\"created_at\":-1");
  expect_throw([&] { (void)deserialize_nostr_event_json(negative_timestamp); },
               "non-negative integer", "negative timestamp");

  const std::string duplicate_id =
      "{\"id\":\"" + id_hex + "\"," + encoded.substr(1);
  expect_throw([&] { (void)deserialize_nostr_event_json(duplicate_id); },
               "duplicate event fields", "duplicate event ID");

  SignedNostrEvent empty_tag = original;
  empty_tag.tags.push_back({});
  expect(!verify_nostr_event(empty_tag, trusted_public_key),
         "an empty Nostr tag is invalid");
  expect_throw([&] { (void)serialize_nostr_event_json(empty_tag); },
               "at least one string", "empty tag serialization");
}

void test_invalid_utf8_is_rejected() {
  const auto public_key = fixed_bytes<32>(
      "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
  UnsignedNostrEvent event = sample_event();
  event.content.push_back(static_cast<char>(0xff));
  expect_throw(
      [&] { (void)serialize_nostr_event_canonical(public_key, event); },
      "invalid UTF-8", "invalid UTF-8 content");
}

}  // namespace

int main() {
  test_bip340_official_vector_zero();
  test_nip01_canonical_serialization_and_id();
  test_event_signing_and_tamper_detection();
  test_wire_json_round_trip_and_strict_parsing();
  test_invalid_utf8_is_rejected();

  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all Nostr event tests passed\n";
  return 0;
}
