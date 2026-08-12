#include "client_bootstrap.h"
#include "nostr_event.h"
#include "util.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace {
int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    ++failures;
  }
}

void expect_throw(const std::function<void()>& action,
                  const std::string& message) {
  try {
    action();
    std::cerr << "FAIL: " << message << " did not throw\n";
    ++failures;
  } catch (const std::runtime_error&) {
  }
}

template <size_t N>
std::array<uint8_t, N> filled(uint8_t value) {
  std::array<uint8_t, N> result{};
  result.fill(value);
  return result;
}

struct TempDirectory {
  std::filesystem::path path =
      std::filesystem::temp_directory_path() /
      ("gitvault-bootstrap-test-" + to_hex(random_bytes(8)));
  ~TempDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
};

ClientBootstrap sample() {
  std::array<uint8_t, 32> secret{};
  secret.back() = 3;
  UnsignedNostrEvent unsigned_event;
  unsigned_event.created_at = 100;
  unsigned_event.kind = 9500;
  unsigned_event.tags = {{"t", std::string(64, 'a')}};
  unsigned_event.content = "encrypted";
  const SignedNostrEvent event = sign_nostr_event(unsigned_event, secret);

  ClientBootstrap value;
  value.vault_name = "vault";
  value.config_bytes = ByteVec{'c', 'o', 'n', 'f', 'i', 'g'};
  value.wrapped_identity = ByteVec(85, 0x42);
  value.channel.vault_id = filled<32>(0x11);
  value.channel.channel_id = filled<32>(0xaa);
  value.channel.vault_public_key = event.public_key;
  value.channel.genesis_event_id = event.id;
  value.channel.config_hash = filled<32>(0x22);
  value.channel.installation_id = std::string(32, 'a');
  value.channel.relay_urls = {
      "wss://one.invalid", "wss://two.invalid", "wss://three.invalid"};
  value.checkpoint.accepted_head = filled<32>(0x33);
  value.checkpoint.head_envelope_hash = filled<32>(0x34);
  value.checkpoint.tip_event_id = event.id;
  value.checkpoint.cloud_revision = "rev-1";
  value.events = {event};
  return value;
}

void test_round_trip_and_no_plain_credentials() {
  TempDirectory temp;
  const auto path = temp.path / "client.bootstrap";
  const ClientBootstrap original = sample();
  write_client_bootstrap(path, original);
  const ClientBootstrap decoded = read_client_bootstrap(path);
  expect(decoded.vault_name == original.vault_name &&
             decoded.config_bytes == original.config_bytes &&
             decoded.wrapped_identity == original.wrapped_identity &&
             decoded.channel.channel_id == original.channel.channel_id &&
             decoded.checkpoint.accepted_head ==
                 original.checkpoint.accepted_head &&
             decoded.events.size() == 1 &&
             decoded.events[0].id == original.events[0].id,
         "bootstrap round-trips exact config, wrapped identity and evidence");
  const ByteVec bytes = read_file_bytes(path);
  const std::string text(bytes.begin(), bytes.end());
  expect(text.find("dropbox") == std::string::npos &&
             text.find("password") == std::string::npos,
         "bootstrap schema has no Dropbox token or plaintext password field");
}

void test_noncanonical_and_duplicate_events_fail_closed() {
  TempDirectory temp;
  const auto path = temp.path / "client.bootstrap";
  write_client_bootstrap(path, sample());
  ByteVec bytes = read_file_bytes(path);
  bytes.insert(bytes.begin(), ' ');
  write_file_bytes(temp.path / "noncanonical", bytes);
  expect_throw([&] { (void)read_client_bootstrap(temp.path / "noncanonical"); },
               "non-canonical bootstrap");

  const ClientBootstrap original = sample();
  const auto duplicate_path = temp.path / "duplicate";
  ClientBootstrap duplicate = original;
  duplicate.events.push_back(original.events[0]);
  write_client_bootstrap(duplicate_path, duplicate);
  expect_throw([&] { (void)read_client_bootstrap(duplicate_path); },
               "duplicate bootstrap event IDs");
}
}  // namespace

int main() {
  test_round_trip_and_no_plain_credentials();
  test_noncanonical_and_duplicate_events_fail_closed();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all client bootstrap tests passed\n";
  return 0;
}
