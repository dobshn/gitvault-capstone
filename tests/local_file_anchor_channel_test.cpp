#include "anchor_channel.h"
#include "local_file_anchor_channel.h"
#include "nostr_event.h"
#include "util.h"

#include <algorithm>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;

struct TempDirectory {
  std::filesystem::path path;

  TempDirectory()
      : path(std::filesystem::temp_directory_path() /
             ("gitvault-anchor-test-" + to_hex(random_bytes(8)))) {}

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

std::array<uint8_t, 32> signing_secret(uint8_t value) {
  std::array<uint8_t, 32> secret{};
  secret.back() = value;
  return secret;
}

SignedNostrEvent make_event(const std::array<uint8_t, 32>& secret,
                            uint64_t created_at,
                            uint16_t kind,
                            const std::string& channel,
                            const std::string& content) {
  UnsignedNostrEvent event;
  event.created_at = created_at;
  event.kind = kind;
  event.tags = {{"channel", channel}, {"format", "gitvault-test"}};
  event.content = content;
  return sign_nostr_event(event, secret);
}

bool events_equal(const SignedNostrEvent& left,
                  const SignedNostrEvent& right) {
  return left.id == right.id && left.public_key == right.public_key &&
         left.created_at == right.created_at && left.kind == right.kind &&
         left.tags == right.tags && left.content == right.content &&
         left.signature == right.signature;
}

void test_publish_and_fetch_through_interface() {
  TempDirectory temp;
  std::unique_ptr<IAnchorChannel> channel =
      std::make_unique<LocalFileAnchorChannel>(temp.path);
  const auto secret = signing_secret(3);
  const SignedNostrEvent original =
      make_event(secret, 100, 9500, "alpha", "event one");

  const auto receipts = channel->publish(original);
  expect(receipts.size() == 1, "local publish returns one endpoint receipt");
  expect(receipts[0].event_id == original.id &&
             receipts[0].status == AnchorPublishStatus::Accepted,
         "first publish reports that the endpoint accepted the event");

  const auto fetched = channel->fetch();
  expect(fetched.size() == 1 && events_equal(fetched[0], original),
         "another caller can fetch the stored event without modification");
  expect(verify_nostr_event(fetched[0], schnorr_public_key(secret)),
         "the caller can verify the fetched event against its Vault key");
}

void test_duplicate_publish_is_idempotent_and_conflicts_do_not_overwrite() {
  TempDirectory temp;
  LocalFileAnchorChannel first_client(temp.path);
  LocalFileAnchorChannel second_client(temp.path);
  const SignedNostrEvent original =
      make_event(signing_secret(3), 101, 9500, "alpha", "immutable");

  first_client.publish(original);
  const auto duplicate_receipts = second_client.publish(original);
  expect(duplicate_receipts.size() == 1 &&
             duplicate_receipts[0].status ==
                 AnchorPublishStatus::AlreadyPresent,
         "publishing the same event through another client is idempotent");
  expect(first_client.fetch().size() == 1,
         "duplicate publish leaves one stored event");

  SignedNostrEvent conflicting = original;
  conflicting.content = "different bytes under the same claimed ID";
  expect_throw([&] { (void)second_client.publish(conflicting); },
               "different anchor event already exists",
               "same ID with different event");
  const auto after_conflict = first_client.fetch();
  expect(after_conflict.size() == 1 &&
             events_equal(after_conflict[0], original),
         "a conflicting publish cannot overwrite the original event");
}

void test_concurrent_publish_installs_one_immutable_event() {
  TempDirectory temp;
  LocalFileAnchorChannel initializer(temp.path);
  const SignedNostrEvent event =
      make_event(signing_secret(3), 102, 9500, "alpha", "concurrent");

  constexpr size_t kClientCount = 8;
  std::mutex mutex;
  std::condition_variable start_condition;
  size_t ready_clients = 0;
  bool start = false;
  std::vector<AnchorPublishStatus> statuses;
  std::vector<std::string> errors;
  std::vector<std::thread> clients;

  for (size_t i = 0; i < kClientCount; ++i) {
    clients.emplace_back([&] {
      LocalFileAnchorChannel client(temp.path);
      {
        std::unique_lock<std::mutex> lock(mutex);
        ready_clients++;
        start_condition.notify_all();
        start_condition.wait(lock, [&] { return start; });
      }
      try {
        const auto receipts = client.publish(event);
        std::lock_guard<std::mutex> lock(mutex);
        statuses.push_back(receipts.at(0).status);
      } catch (const std::exception& error) {
        std::lock_guard<std::mutex> lock(mutex);
        errors.push_back(error.what());
      }
    });
  }

  {
    std::unique_lock<std::mutex> lock(mutex);
    start_condition.wait(lock, [&] { return ready_clients == kClientCount; });
    start = true;
  }
  start_condition.notify_all();
  for (auto& client : clients) {
    client.join();
  }

  const size_t accepted = static_cast<size_t>(std::count(
      statuses.begin(), statuses.end(), AnchorPublishStatus::Accepted));
  const size_t already_present = static_cast<size_t>(std::count(
      statuses.begin(), statuses.end(), AnchorPublishStatus::AlreadyPresent));
  expect(errors.empty(), "concurrent identical publishes do not fail");
  expect(accepted == 1 && already_present == kClientCount - 1,
         "one client installs the event and the others observe the same ID");
  expect(initializer.fetch().size() == 1,
         "concurrent publishing leaves exactly one immutable event file");
}

void test_query_filters_and_deterministic_fetch_order() {
  TempDirectory temp;
  LocalFileAnchorChannel channel(temp.path);
  const auto first_secret = signing_secret(3);
  const auto second_secret = signing_secret(4);

  const std::vector<SignedNostrEvent> input = {
      make_event(first_secret, 400, 9500, "alpha", "matching"),
      make_event(first_secret, 100, 9500, "beta", "wrong channel"),
      make_event(second_secret, 200, 9500, "alpha", "wrong author"),
      make_event(first_secret, 300, 9501, "alpha", "wrong kind"),
  };
  for (const auto& event : input) {
    channel.publish(event);
  }

  AnchorChannelQuery query;
  query.author = schnorr_public_key(first_secret);
  query.kind = 9500;
  query.required_tags = {{"channel", "alpha"}};
  const auto filtered = channel.fetch(query);
  expect(filtered.size() == 1 && filtered[0].content == "matching",
         "author, kind, and exact tag filters are combined");

  const auto all_events = channel.fetch();
  std::vector<std::string> event_ids;
  for (const auto& event : all_events) {
    event_ids.push_back(to_hex(event.id));
  }
  expect(std::is_sorted(event_ids.begin(), event_ids.end()),
         "local fetch order is deterministic by event ID, not timestamp");
}

void test_channel_returns_untrusted_events_for_caller_verification() {
  TempDirectory temp;
  LocalFileAnchorChannel channel(temp.path);
  const auto trusted_secret = signing_secret(3);
  const auto attacker_secret = signing_secret(4);
  const SignedNostrEvent trusted =
      make_event(trusted_secret, 100, 9500, "alpha", "trusted");
  const SignedNostrEvent attacker =
      make_event(attacker_secret, 101, 9500, "alpha", "attacker");

  channel.publish(trusted);
  channel.publish(attacker);
  const auto fetched = channel.fetch();
  const SchnorrPublicKey trusted_public_key =
      schnorr_public_key(trusted_secret);
  const size_t accepted = static_cast<size_t>(std::count_if(
      fetched.begin(), fetched.end(), [&](const SignedNostrEvent& event) {
        return verify_nostr_event(event, trusted_public_key);
      }));
  expect(fetched.size() == 2 && accepted == 1,
         "the channel transports an attacker event but Vault verification rejects it");
}

void test_tampered_and_malformed_storage_is_observable() {
  TempDirectory tampered_temp;
  LocalFileAnchorChannel tampered_channel(tampered_temp.path);
  const auto secret = signing_secret(3);
  const SignedNostrEvent original =
      make_event(secret, 100, 9500, "alpha", "before tampering");
  tampered_channel.publish(original);

  SignedNostrEvent tampered = original;
  tampered.content = "after tampering";
  const std::string tampered_json = serialize_nostr_event_json(tampered);
  write_file_bytes(
      tampered_temp.path / "events" / (to_hex(original.id) + ".json"),
      ByteVec(tampered_json.begin(), tampered_json.end()));
  const auto fetched_tampered = tampered_channel.fetch();
  expect(fetched_tampered.size() == 1 &&
             !verify_nostr_event(fetched_tampered[0],
                                 schnorr_public_key(secret)),
         "well-formed storage tampering is returned and rejected by verification");

  TempDirectory malformed_temp;
  LocalFileAnchorChannel malformed_channel(malformed_temp.path);
  write_file_bytes(malformed_temp.path / "events" /
                       (std::string(64, '0') + ".json"),
                   ByteVec{'{', 'x', '}'});
  expect_throw([&] { (void)malformed_channel.fetch(); },
               "invalid Nostr event JSON", "malformed stored event");
}

void test_empty_root_is_rejected() {
  expect_throw(
      [] { LocalFileAnchorChannel channel(std::filesystem::path{}); },
      "root must not be empty", "empty channel root");
}

}  // namespace

int main() {
  test_publish_and_fetch_through_interface();
  test_duplicate_publish_is_idempotent_and_conflicts_do_not_overwrite();
  test_concurrent_publish_installs_one_immutable_event();
  test_query_filters_and_deterministic_fetch_order();
  test_channel_returns_untrusted_events_for_caller_verification();
  test_tampered_and_malformed_storage_is_observable();
  test_empty_root_is_rejected();

  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all local anchor channel tests passed\n";
  return 0;
}
