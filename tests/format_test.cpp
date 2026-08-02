#include "format.h"

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
  } catch (const std::runtime_error& ex) {
    if (std::string(ex.what()).find(expected_message) == std::string::npos) {
      std::cerr << "FAIL: " << test_name << " threw unexpected error: " << ex.what() << "\n";
      failures++;
    }
  }
}

std::array<uint8_t, 32> filled_hash(uint8_t value) {
  std::array<uint8_t, 32> hash{};
  hash.fill(value);
  return hash;
}

void test_v2_round_trip() {
  Commit input;
  input.commit_time = 123456789;
  input.root_hash = filled_hash(0x11);
  input.parent_hash = filled_hash(0x22);

  ByteVec encoded = serialize_commit(input);
  Commit output = deserialize_commit(encoded);

  expect(encoded.size() == 73, "V2 serialized size is 73 bytes");
  expect(output.version == 2, "V2 version round-trips");
  expect(output.commit_time == input.commit_time, "V2 commit time round-trips");
  expect(output.root_hash == input.root_hash, "V2 root hash round-trips");
  expect(output.parent_hash == input.parent_hash, "V2 parent hash round-trips");
}

void test_v2_genesis_parent() {
  Commit input;
  input.root_hash = filled_hash(0x33);

  Commit output = deserialize_commit(serialize_commit(input));
  expect(output.parent_hash == std::array<uint8_t, 32>{},
         "V2 initial commit keeps the zero parent sentinel");
}

void test_v1_is_rejected() {
  Commit input;
  input.version = 1;
  expect_throw([&] { serialize_commit(input); },
               "unsupported commit version",
               "serialize V1 commit");

  ByteVec encoded(41, 0);
  encoded[0] = 1;
  expect_throw([&] { deserialize_commit(encoded); },
               "unsupported commit version",
               "deserialize V1 commit");
}

void test_malformed_commit_sizes_are_rejected() {
  Commit v2;
  ByteVec truncated = serialize_commit(v2);
  truncated.pop_back();
  expect_throw([&] { deserialize_commit(truncated); },
               "invalid commit size for version 2",
               "truncated V2 commit");

  Commit v2_extended;
  ByteVec extended = serialize_commit(v2_extended);
  extended.push_back(0);
  expect_throw([&] { deserialize_commit(extended); },
               "invalid commit size for version 2",
               "extended V2 commit");
}

void test_unknown_versions_are_rejected() {
  Commit input;
  input.version = 3;
  expect_throw([&] { serialize_commit(input); },
               "unsupported commit version",
               "serialize unknown commit version");

  ByteVec encoded(1, 3);
  expect_throw([&] { deserialize_commit(encoded); },
               "unsupported commit version",
               "deserialize unknown commit version");
}

}  // namespace

int main() {
  test_v2_round_trip();
  test_v2_genesis_parent();
  test_v1_is_rejected();
  test_malformed_commit_sizes_are_rejected();
  test_unknown_versions_are_rejected();

  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all format tests passed\n";
  return 0;
}
