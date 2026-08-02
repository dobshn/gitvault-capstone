#include "crypto/CryptoImpl.h"
#include "crypto/hkdf.h"
#include "util.h"
#include "vault_identity.h"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int failures = 0;

struct TempDirectory {
  std::filesystem::path path;

  ~TempDirectory() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

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
  } catch (const std::runtime_error& ex) {
    if (std::string(ex.what()).find(expected_message) == std::string::npos) {
      std::cerr << "FAIL: " << test_name << " threw unexpected error: " << ex.what() << "\n";
      failures++;
    }
  }
}

Keys derive_test_keys(const std::string& password) {
  CryptoImpl crypto;
  ByteVec salt(16, 0x5a);
  return crypto.derive_keys(salt, 100, password);
}

void test_generated_identity_round_trip() {
  const Keys keys = derive_test_keys("correct horse battery staple");
  const VaultIdentity input = generate_vault_identity();

  const ByteVec wrapped = wrap_vault_identity(input, keys);
  const VaultIdentity output = unwrap_vault_identity(wrapped, keys);

  expect(is_valid_vault_signing_secret(input.signing_secret),
         "generated signing secret is a valid secp256k1 scalar");
  expect(wrapped.size() == 85, "wrapped identity has the fixed 85-byte format");
  expect(output.version == input.version, "identity version round-trips");
  expect(output.signing_secret == input.signing_secret, "signing secret round-trips");
}

void test_secp256k1_scalar_boundaries() {
  std::array<uint8_t, 32> one{};
  one.back() = 1;
  expect(is_valid_vault_signing_secret(one), "scalar one is valid");

  const auto order = hash_from_hex(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  expect(!is_valid_vault_signing_secret(order), "the secp256k1 group order is invalid");

  auto largest_valid = order;
  largest_valid.back()--;
  expect(is_valid_vault_signing_secret(largest_valid), "group order minus one is valid");
}

void test_wrapping_uses_a_fresh_iv() {
  const Keys keys = derive_test_keys("same password");
  const VaultIdentity identity = generate_vault_identity();

  const ByteVec first = wrap_vault_identity(identity, keys);
  const ByteVec second = wrap_vault_identity(identity, keys);
  expect(first != second, "wrapping the same identity twice produces different bytes");
}

void test_wrong_password_and_tampering_are_rejected() {
  const Keys correct_keys = derive_test_keys("correct password");
  const Keys wrong_keys = derive_test_keys("wrong password");
  const VaultIdentity identity = generate_vault_identity();
  const ByteVec wrapped = wrap_vault_identity(identity, correct_keys);

  expect_throw([&] { (void)unwrap_vault_identity(wrapped, wrong_keys); },
               "vault identity authentication failed",
               "wrong password");

  ByteVec tampered_ciphertext = wrapped;
  tampered_ciphertext[24] ^= 0x01;
  expect_throw([&] { (void)unwrap_vault_identity(tampered_ciphertext, correct_keys); },
               "vault identity authentication failed",
               "tampered ciphertext");

  ByteVec tampered_tag = wrapped;
  tampered_tag.back() ^= 0x01;
  expect_throw([&] { (void)unwrap_vault_identity(tampered_tag, correct_keys); },
               "vault identity authentication failed",
               "tampered authentication tag");
}

void test_format_and_invalid_secret_are_rejected() {
  const Keys keys = derive_test_keys("format password");
  const ByteVec wrapped = wrap_vault_identity(generate_vault_identity(), keys);

  ByteVec truncated = wrapped;
  truncated.pop_back();
  expect_throw([&] { (void)unwrap_vault_identity(truncated, keys); },
               "invalid wrapped vault identity size",
               "truncated identity");

  ByteVec bad_magic = wrapped;
  bad_magic[0] ^= 0x01;
  expect_throw([&] { (void)unwrap_vault_identity(bad_magic, keys); },
               "invalid wrapped vault identity magic",
               "bad identity magic");

  ByteVec bad_version = wrapped;
  bad_version[4] = 2;
  expect_throw([&] { (void)unwrap_vault_identity(bad_version, keys); },
               "unsupported vault identity version",
               "unknown identity version");

  VaultIdentity invalid_identity;
  expect_throw([&] { (void)wrap_vault_identity(invalid_identity, keys); },
               "invalid vault signing secret",
               "zero signing secret");
}

void test_key_domain_separation() {
  const Keys first = derive_test_keys("domain separation");
  const Keys second = derive_test_keys("domain separation");

  expect(first.enc_key == second.enc_key && first.mac_key == second.mac_key &&
             first.wrap_enc_key == second.wrap_enc_key &&
             first.wrap_mac_key == second.wrap_mac_key,
         "the same password and salt derive the same keys");
  expect(first.wrap_enc_key.size() == 32 && first.wrap_mac_key.size() == 32,
         "wrapping subkeys are 32 bytes");
  expect(first.wrap_enc_key != first.enc_key && first.wrap_enc_key != first.mac_key,
         "wrapping encryption key is separate from existing keys");
  expect(first.wrap_mac_key != first.enc_key && first.wrap_mac_key != first.mac_key &&
             first.wrap_mac_key != first.wrap_enc_key,
         "wrapping authentication key has a distinct domain");
  expect(first.enc_key ==
             from_hex("e43860405c2f82a674fd5272efcb7c5edc4575d127b3deca33902633805e0fb0") &&
             first.mac_key ==
             from_hex("36b002288919c1460bf6ab0d9901006dc1a28558e3add32a7161855a6005862c") &&
             first.wrap_enc_key ==
             from_hex("37856265362d0d7f6290ce7c7c0dd3c87cced17062d0ed35fd9b0772f3244742") &&
             first.wrap_mac_key ==
             from_hex("dd23a0867a0fa1a05de26249f8e1c4f98f10081cdc885ea3219b2ef79ef5fb45"),
         "the V2 key schedule matches its fixed derivation vector");
}

void test_hkdf_rfc5869_vector() {
  const ByteVec input_key_material(22, 0x0b);
  const ByteVec salt = from_hex("000102030405060708090a0b0c");
  const ByteVec info = from_hex("f0f1f2f3f4f5f6f7f8f9");
  const ByteVec expected = from_hex(
      "3cb25f25faacd57a90434f64d0362f2a"
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865");

  expect(hkdf_sha256(input_key_material, salt, info, 42) == expected,
         "HKDF-SHA256 matches RFC 5869 test case 1");
}

void test_private_file_installation() {
  TempDirectory temp{
      std::filesystem::temp_directory_path() /
      ("gitvault-identity-test-" + to_hex(random_bytes(8)))};
  const std::filesystem::path path = temp.path / "trust" / "vault-identity.enc";
  const Keys keys = derive_test_keys("file password");
  const ByteVec wrapped = wrap_vault_identity(generate_vault_identity(), keys);

  save_wrapped_vault_identity_file(path, wrapped);
  expect(load_wrapped_vault_identity_file(path) == wrapped,
         "installed identity file can be read without modification");

  const auto public_bits = std::filesystem::perms::group_all |
                           std::filesystem::perms::others_all;
  const auto directory_permissions = std::filesystem::status(path.parent_path()).permissions();
  const auto file_permissions = std::filesystem::status(path).permissions();
  expect(directory_permissions == std::filesystem::perms::owner_all,
         "trust directory permissions are 0700");
  expect(file_permissions == (std::filesystem::perms::owner_read |
                              std::filesystem::perms::owner_write),
         "identity file permissions are 0600");
  expect((directory_permissions & public_bits) == std::filesystem::perms::none,
         "trust directory is inaccessible to group and other users");
  expect((file_permissions & public_bits) == std::filesystem::perms::none,
         "identity file is inaccessible to group and other users");

  expect_throw([&] { save_wrapped_vault_identity_file(path, wrapped); },
               "vault identity already exists",
               "identity overwrite");
  expect(load_wrapped_vault_identity_file(path) == wrapped,
         "rejected overwrite leaves the original identity unchanged");
}

}  // namespace

int main() {
  test_generated_identity_round_trip();
  test_secp256k1_scalar_boundaries();
  test_wrapping_uses_a_fresh_iv();
  test_wrong_password_and_tampering_are_rejected();
  test_format_and_invalid_secret_are_rejected();
  test_key_domain_separation();
  test_hkdf_rfc5869_vector();
  test_private_file_installation();

  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all vault identity tests passed\n";
  return 0;
}
