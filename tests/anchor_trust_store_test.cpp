#include "anchor_trust_store.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>

#include "crypto/schnorr.h"
#include "util.h"

namespace {
int failures = 0;

struct TempDirectory {
  std::filesystem::path path =
      std::filesystem::temp_directory_path() /
      ("gitvault-trust-test-" + to_hex(random_bytes(8)));
  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

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
std::array<uint8_t, N> filled(uint8_t value) {
  std::array<uint8_t, N> result{};
  result.fill(value);
  return result;
}

std::array<uint8_t, 32> signing_secret() {
  std::array<uint8_t, 32> secret{};
  secret.back() = 3;
  return secret;
}

SignedNostrEvent sample_event() {
  UnsignedNostrEvent event;
  event.created_at = 123;
  event.kind = kGitVaultAnchorEventKind;
  event.tags = {{"t", std::string(64, 'a')}};
  event.content = "encrypted-content-placeholder";
  return sign_nostr_event(event, signing_secret());
}

void test_authenticated_metadata_and_tamper_detection() {
  TempDirectory temp;
  ByteVec mac_key(32, 0x44);
  AnchorTrustStore store(temp.path / "trust", mac_key);

  AnchorChannelConfig channel;
  channel.vault_id = filled<32>(0x11);
  channel.channel_id = filled<32>(0x12);
  channel.vault_public_key = schnorr_public_key(signing_secret());
  channel.genesis_event_id = filled<32>(0x13);
  channel.config_hash = filled<32>(0x14);
  channel.installation_id = std::string(32, 'a');
  channel.relay_urls = {"wss://one.example", "wss://two.example",
                        "wss://three.example"};
  store.save_channel(channel);
  const AnchorChannelConfig loaded = store.load_channel();
  expect(loaded.vault_id == channel.vault_id &&
             loaded.channel_id == channel.channel_id &&
             loaded.relay_urls == channel.relay_urls &&
             loaded.read_quorum == 2,
         "channel metadata round-trips under its MAC");

  AnchorCheckpoint checkpoint;
  checkpoint.accepted_head = filled<32>(0x21);
  checkpoint.tip_event_id = filled<32>(0x22);
  checkpoint.cloud_revision = "0123456789abcdef";
  store.save_checkpoint(checkpoint);
  expect(store.load_checkpoint().accepted_head == checkpoint.accepted_head,
         "checkpoint round-trips under its MAC");

  const auto checkpoint_path = temp.path / "trust" / "checkpoint.json";
  ByteVec bytes = read_file_bytes(checkpoint_path);
  const std::string needle(64, '2');
  std::string text(bytes.begin(), bytes.end());
  const size_t position = text.find(needle);
  expect(position != std::string::npos,
         "test locates the checkpoint hash inside its envelope");
  text[position] = '3';
  write_file_bytes(checkpoint_path, ByteVec(text.begin(), text.end()));
  expect_throw([&] { (void)store.load_checkpoint(); },
               "tampered checkpoint is rejected");
}

void test_prepared_event_cache_and_outbox() {
  TempDirectory temp;
  AnchorTrustStore store(temp.path / "trust", ByteVec(32, 0x55));

  PreparedWriteRecord prepared;
  prepared.operation_id = filled<16>(0x31);
  prepared.previous_head = filled<32>(0x32);
  prepared.new_head = filled<32>(0x33);
  prepared.encrypted_head_bytes = ByteVec(80, 0x34);
  prepared.phase = PreparedWritePhase::ProposalPublished;
  prepared.proposal_event_id = filled<32>(0x35);
  prepared.cloud_revision = "rev-before-cas";
  store.save_prepared(prepared);
  const PreparedWriteRecord loaded = store.load_prepared();
  expect(loaded.operation_id == prepared.operation_id &&
             loaded.new_head == prepared.new_head &&
             loaded.phase == prepared.phase &&
             loaded.proposal_event_id == prepared.proposal_event_id,
         "prepared write journal round-trips every recovery field");
  store.clear_prepared();
  expect(!store.prepared_exists(), "prepared journal can be durably cleared");

  const SignedNostrEvent event = sample_event();
  store.cache_event(event);
  store.cache_event(event);
  expect(store.load_cached_events().size() == 1,
         "event cache is immutable and idempotent by event ID");

  AnchorOutboxRecord outbox;
  outbox.event = event;
  outbox.accepted_endpoints = {"wss://one.example"};
  store.save_outbox(outbox);
  const auto records = store.load_outbox();
  expect(records.size() == 1 &&
             records[0].accepted_endpoints == outbox.accepted_endpoints,
         "outbox persists relay acknowledgement progress");
  store.remove_outbox(event.id);
  expect(store.load_outbox().empty(), "completed outbox event is removed");
}
}  // namespace

int main() {
  test_authenticated_metadata_and_tamper_detection();
  test_prepared_event_cache_and_outbox();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all anchor trust store tests passed\n";
  return 0;
}
