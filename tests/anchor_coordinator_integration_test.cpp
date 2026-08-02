#include "API.h"
#include "anchor_coordinator.h"
#include "anchor_trust_store.h"
#include "object_store.h"
#include "util.h"
#include "vault_engine.h"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>

namespace {
int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    ++failures;
  }
}

struct TempDirectory {
  std::filesystem::path path =
      std::filesystem::temp_directory_path() /
      ("gitvault-coordinator-test-" + to_hex(random_bytes(8)));
  ~TempDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
};

struct RemoteFile {
  ByteVec bytes;
  std::string revision;
};

struct SharedCloud {
  std::mutex mutex;
  std::map<std::string, RemoteFile> files;
  uint64_t next_revision = 1;
  bool conflict_next_conditional_write = false;
  size_t remove_calls = 0;
};

class FakeCloudApi final : public API {
public:
  explicit FakeCloudApi(std::shared_ptr<SharedCloud> cloud)
      : cloud_(std::move(cloud)) {}

  void init(std::string, std::string) override {}
  void fetch(std::string, std::string) override {}
  bool destroy(std::string, std::string) override { return true; }

  void put(std::string_view path,
           const ByteVec& data,
           bool overwrite) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    const std::string key(path);
    if (!overwrite && cloud_->files.count(key) != 0) {
      throw std::runtime_error("fake add conflict");
    }
    cloud_->files[key] = {data, next_revision()};
  }

  ByteVec get(std::string_view path) const override {
    return get_versioned(path).bytes;
  }

  VersionedBytes get_versioned(std::string_view path) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    const auto found = cloud_->files.find(std::string(path));
    if (found == cloud_->files.end()) {
      throw std::runtime_error("fake cloud object not found");
    }
    return {found->second.bytes, found->second.revision};
  }

  ConditionalWriteResult put_if_revision(
      std::string_view path,
      const ByteVec& data,
      std::string_view expected_revision) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    if (cloud_->conflict_next_conditional_write) {
      cloud_->conflict_next_conditional_write = false;
      return {ConditionalWriteStatus::Conflict, {}};
    }
    const auto found = cloud_->files.find(std::string(path));
    if (found == cloud_->files.end() ||
        found->second.revision != expected_revision) {
      return {ConditionalWriteStatus::Conflict, {}};
    }
    const std::string revision = next_revision();
    found->second = {data, revision};
    return {ConditionalWriteStatus::Updated, revision};
  }

  ConditionalWriteResult put_if_absent(
      std::string_view path,
      const ByteVec& data) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    const std::string key(path);
    if (cloud_->files.count(key) != 0) {
      return {ConditionalWriteStatus::Conflict, {}};
    }
    const std::string revision = next_revision();
    cloud_->files[key] = {data, revision};
    return {ConditionalWriteStatus::Updated, revision};
  }

  bool exists(std::string_view path) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    return cloud_->files.count(std::string(path)) != 0;
  }

  bool remove(std::string_view path) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    ++cloud_->remove_calls;
    return cloud_->files.erase(std::string(path)) != 0;
  }

private:
  std::string next_revision() const {
    return "rev-" + std::to_string(cloud_->next_revision++);
  }
  std::shared_ptr<SharedCloud> cloud_;
};

struct SharedAnchor {
  std::mutex mutex;
  std::map<AnchorHash, SignedNostrEvent> events;
  size_t accepted_relay_count = 3;
  size_t synchronized_relay_count = 3;
  size_t publish_count = 0;
  size_t reduce_sync_after_publish_count =
      std::numeric_limits<size_t>::max();
};

class ThreeRelayChannel final : public IAnchorChannel {
public:
  ThreeRelayChannel(std::shared_ptr<SharedAnchor> anchor,
                    std::vector<std::string> endpoints)
      : anchor_(std::move(anchor)), endpoints_(std::move(endpoints)) {}

  AnchorPublishResult publish(const SignedNostrEvent& event) override {
    AnchorPublishStatus status = AnchorPublishStatus::Accepted;
    size_t accepted_relay_count = 0;
    {
      std::lock_guard<std::mutex> lock(anchor_->mutex);
      ++anchor_->publish_count;
      accepted_relay_count = anchor_->accepted_relay_count;
      const auto [found, inserted] = anchor_->events.emplace(event.id, event);
      if (!inserted) {
        if (serialize_nostr_event_json(found->second) !=
            serialize_nostr_event_json(event)) {
          throw std::runtime_error("fake relay immutable conflict");
        }
        status = AnchorPublishStatus::AlreadyPresent;
      }
    }
    AnchorPublishResult result;
    for (size_t index = 0; index < endpoints_.size(); ++index) {
      const AnchorPublishStatus endpoint_status =
          index < accepted_relay_count ? status
                                       : AnchorPublishStatus::Timeout;
      result.endpoints.push_back(
          {endpoints_[index], event.id, endpoint_status, {}, 0});
    }
    return result;
  }

  AnchorFetchResult fetch(const AnchorChannelQuery& query) const override {
    AnchorFetchResult result;
    size_t synchronized_relay_count = 0;
    {
      std::lock_guard<std::mutex> lock(anchor_->mutex);
      synchronized_relay_count =
          anchor_->publish_count >= anchor_->reduce_sync_after_publish_count
              ? anchor_->synchronized_relay_count
              : endpoints_.size();
      for (const auto& [id, event] : anchor_->events) {
        (void)id;
        if (query.author.has_value() && event.public_key != *query.author) {
          continue;
        }
        if (query.kind.has_value() && event.kind != *query.kind) continue;
        bool tags_match = true;
        for (const auto& required : query.required_tags) {
          if (std::find(event.tags.begin(), event.tags.end(), required) ==
              event.tags.end()) {
            tags_match = false;
          }
        }
        if (tags_match) result.events.push_back(event);
      }
    }
    for (size_t index = 0; index < endpoints_.size(); ++index) {
      result.endpoints.push_back(
          {endpoints_[index],
           index < synchronized_relay_count
               ? AnchorFetchStatus::Synchronized
               : AnchorFetchStatus::TransportError,
           index < synchronized_relay_count ? "" : "injected relay failure",
           0});
    }
    return result;
  }

private:
  std::shared_ptr<SharedAnchor> anchor_;
  std::vector<std::string> endpoints_;
};

size_t object_count(const std::shared_ptr<SharedCloud>& cloud) {
  std::lock_guard<std::mutex> lock(cloud->mutex);
  return static_cast<size_t>(std::count_if(
      cloud->files.begin(), cloud->files.end(), [](const auto& item) {
        return item.first.rfind("objects/", 0) == 0;
      }));
}

void install_second_client(ObjectStore& source_store,
                           VaultEngine& source_engine,
                           ObjectStore& target_store,
                           const std::string& password) {
  AnchorTrustStore source_trust(source_store.trust_directory(),
                                source_engine.trust_mac_key());
  target_store.write_local_config_bytes(
      source_store.read_local_config_bytes());
  target_store.save_vault_identity(source_store.load_vault_identity());
  VaultEngine target_engine(target_store, password);
  AnchorTrustStore target_trust(target_store.trust_directory(),
                                target_engine.trust_mac_key());
  AnchorChannelConfig channel = source_trust.load_channel();
  channel.installation_id = "device-b";
  target_trust.save_channel(channel);
  const AnchorCheckpoint checkpoint = source_trust.load_checkpoint();
  target_trust.save_checkpoint(checkpoint);
  for (const auto& event : source_trust.load_cached_events()) {
    target_trust.cache_event(event);
  }
  target_store.write_local_head(
      target_engine.encrypt_head(checkpoint.accepted_head));
}

void test_two_clients_catch_up_and_cas_is_append_only() {
  TempDirectory temp;
  const std::string password = "integration-password";
  const std::vector<std::string> endpoints = {
      "wss://relay-one.invalid", "wss://relay-two.invalid",
      "wss://relay-three.invalid"};
  auto cloud = std::make_shared<SharedCloud>();
  auto anchor = std::make_shared<SharedAnchor>();

  ObjectStore store_a(std::make_unique<FakeCloudApi>(cloud), temp.path / "a");
  store_a.init("token", "vault");
  VaultEngine engine_a(store_a, password, true);
  const AnchorHash h0 = engine_a.init_vault();
  ThreeRelayChannel init_channel(anchor, endpoints);
  const AnchorChannelConfig initialized = AnchorCoordinator::initialize(
      store_a, engine_a, init_channel, endpoints);

  AnchorTrustStore interrupted_trust(
      store_a.trust_directory(), engine_a.trust_mac_key());
  const SignedNostrEvent genesis =
      interrupted_trust.load_cached_events().front();
  std::filesystem::remove(store_a.trust_directory() / "checkpoint.json");
  std::filesystem::remove(store_a.trust_directory() / "events" /
                          (to_hex(initialized.genesis_event_id) + ".json"));
  interrupted_trust.save_outbox({genesis, {}});
  AnchorCoordinator initialization_recovery(
      store_a, engine_a,
      std::make_unique<ThreeRelayChannel>(anchor, endpoints));
  const AnchorCoordinatorStatus recovered_init =
      initialization_recovery.preflight(false);
  expect(interrupted_trust.checkpoint_exists() &&
             recovered_init.decision.state == AnchorClientState::Consistent,
         "missing Genesis checkpoint recovers from the durable outbox");

  ObjectStore store_b(std::make_unique<FakeCloudApi>(cloud), temp.path / "b");
  store_b.fetch("token", "vault");
  install_second_client(store_a, engine_a, store_b, password);
  VaultEngine engine_b(store_b, password);

  AnchorCoordinator coordinator_a(
      store_a, engine_a,
      std::make_unique<ThreeRelayChannel>(anchor, endpoints));
  AnchorCoordinator coordinator_b(
      store_b, engine_b,
      std::make_unique<ThreeRelayChannel>(anchor, endpoints));

  const PreparedVaultWrite first = coordinator_a.execute_write(
      [&](const AnchorHash& base) {
        return engine_a.prepare_mkdir("from-a", base);
      });
  expect(first.previous_head == h0 && first.new_head != h0,
         "A publishes a linear transition from Genesis");

  const AnchorCoordinatorStatus b_catch_up = coordinator_b.preflight(false);
  expect(b_catch_up.decision.state == AnchorClientState::LocalCatchUp &&
             b_catch_up.local_head == first.new_head,
         "B at H0 safely adopts C=N=H1");
  const AnchorCoordinatorStatus b_consistent = coordinator_b.preflight(false);
  expect(b_consistent.decision.state == AnchorClientState::Consistent,
         "B reaches CONSISTENT after catch-up");

  const PreparedVaultWrite second = coordinator_b.execute_write(
      [&](const AnchorHash& base) {
        return engine_b.prepare_mkdir("from-b", base);
      });
  expect(second.previous_head == first.new_head,
         "B can write only after using the verified H1 parent");

  (void)coordinator_a.preflight(false);
  (void)coordinator_a.preflight(false);
  const size_t objects_before_conflict = object_count(cloud);
  {
    std::lock_guard<std::mutex> lock(cloud->mutex);
    cloud->conflict_next_conditional_write = true;
  }
  bool conflict_observed = false;
  try {
    (void)coordinator_a.execute_write([&](const AnchorHash& base) {
      return engine_a.prepare_mkdir("losing-write", base);
    });
  } catch (const std::runtime_error& error) {
    conflict_observed =
        std::string(error.what()).find("CAS conflict") != std::string::npos;
  }
  expect(conflict_observed, "stale Dropbox revision is reported as CAS conflict");
  expect(object_count(cloud) > objects_before_conflict,
         "objects prepared before a CAS conflict remain append-only");
  expect(cloud->remove_calls == 0,
         "no Tree or Blob is deleted during updates or CAS failure");

  {
    std::lock_guard<std::mutex> lock(anchor->mutex);
    anchor->accepted_relay_count = 1;
  }
  bool quorum_failure = false;
  try {
    (void)coordinator_a.execute_write([&](const AnchorHash& base) {
      return engine_a.prepare_mkdir("resume-after-w1", base);
    });
  } catch (const std::runtime_error& error) {
    quorum_failure =
        std::string(error.what()).find("W=2") != std::string::npos;
  }
  AnchorTrustStore pending_trust(store_a.trust_directory(),
                                 engine_a.trust_mac_key());
  expect(quorum_failure && pending_trust.prepared_exists() &&
             !pending_trust.load_outbox().empty(),
         "W=1 leaves an authenticated prepared journal and outbox");
  {
    std::lock_guard<std::mutex> lock(anchor->mutex);
    anchor->accepted_relay_count = 3;
  }
  const AnchorCoordinatorStatus resumed = coordinator_a.preflight(false);
  expect(!pending_trust.prepared_exists() &&
             resumed.cloud_head == resumed.observed_head,
         "the next command resumes a W=1 interrupted write without loss");

  const VersionedBytes versioned = store_a.read_cloud_head_versioned();
  const ConditionalWriteResult stale = store_a.compare_exchange_cloud_head(
      versioned.bytes, "stale-revision");
  expect(stale.status == ConditionalWriteStatus::Conflict,
         "ObjectStore preserves the revision-CAS contract");
}

void test_observation_w2_completes_before_final_read_quorum() {
  TempDirectory temp;
  const std::string password = "integration-password";
  const std::vector<std::string> endpoints = {
      "wss://relay-one.invalid", "wss://relay-two.invalid",
      "wss://relay-three.invalid"};
  auto cloud = std::make_shared<SharedCloud>();
  auto anchor = std::make_shared<SharedAnchor>();

  ObjectStore store(std::make_unique<FakeCloudApi>(cloud), temp.path / "a");
  store.init("token", "vault");
  VaultEngine engine(store, password, true);
  const AnchorHash initial_head = engine.init_vault();
  ThreeRelayChannel init_channel(anchor, endpoints);
  AnchorChannelConfig channel_config = AnchorCoordinator::initialize(
      store, engine, init_channel, endpoints);
  AnchorTrustStore trust(store.trust_directory(), engine.trust_mac_key());
  const AnchorCheckpoint initial_checkpoint = trust.load_checkpoint();
  channel_config.read_quorum = 3;
  trust.save_channel(channel_config);

  {
    std::lock_guard<std::mutex> lock(anchor->mutex);
    anchor->accepted_relay_count = 2;
    anchor->synchronized_relay_count = 1;
    anchor->reduce_sync_after_publish_count = anchor->publish_count + 2;
  }
  AnchorCoordinator coordinator(
      store, engine,
      std::make_unique<ThreeRelayChannel>(anchor, endpoints));
  channel_config = trust.load_channel();
  expect(coordinator.config().read_quorum == 2 &&
             channel_config.read_quorum == 2,
         "an authenticated legacy R=3 policy migrates to R=2");
  const PreparedVaultWrite write = coordinator.execute_write(
      [&](const AnchorHash& base) {
        return engine.prepare_mkdir("completed-at-w2", base);
      });

  const AnchorCheckpoint checkpoint = trust.load_checkpoint();
  expect(write.previous_head == initial_head &&
             checkpoint.accepted_head == write.new_head &&
             engine.decrypt_head(store.read_local_head()) == write.new_head &&
             engine.decrypt_head(store.read_cloud_head_versioned().bytes) ==
                 write.new_head,
         "Observation W=2 and cloud readback advance local checkpoint");
  expect(!trust.prepared_exists() && trust.load_outbox().empty(),
         "completed W=2 write clears its prepared journal and outbox");

  const AnchorCoordinatorStatus degraded = coordinator.preflight(true);
  expect(degraded.decision.state == AnchorClientState::DegradedReadOnly &&
             !degraded.observed_head.has_value() &&
             degraded.cloud_observed_relation == "unavailable",
         "incomplete relay sync reports N as unavailable after completion");

  SignedNostrEvent proposal_event;
  SignedNostrEvent observation_event;
  HeadProposalEvent proposal_payload;
  bool found_proposal = false;
  bool found_observation = false;
  for (const auto& event : trust.load_cached_events()) {
    const AnchorEventPayload payload = verify_decrypt_anchor_event(
        event, channel_config.vault_public_key,
        engine.identity().signing_secret);
    if (const auto* proposal = std::get_if<HeadProposalEvent>(&payload);
        proposal != nullptr && proposal->new_head == write.new_head) {
      proposal_event = event;
      proposal_payload = *proposal;
      found_proposal = true;
    }
    if (const auto* observation =
            std::get_if<HeadObservationEvent>(&payload);
        observation != nullptr &&
        observation->observed_cloud_head == write.new_head) {
      observation_event = event;
      found_observation = true;
    }
  }
  expect(found_proposal && found_observation,
         "completed write caches its Proposal and Observation");

  const VersionedBytes committed_cloud = store.read_cloud_head_versioned();
  trust.save_checkpoint(initial_checkpoint);
  store.write_local_head(engine.encrypt_head(initial_head));
  PreparedWriteRecord interrupted;
  interrupted.operation_id = proposal_payload.common.operation_id;
  interrupted.previous_head = initial_head;
  interrupted.new_head = write.new_head;
  interrupted.encrypted_head_bytes = committed_cloud.bytes;
  interrupted.phase = PreparedWritePhase::ObservationPublished;
  interrupted.proposal_event_id = proposal_event.id;
  interrupted.observation_event_id = observation_event.id;
  interrupted.cloud_revision = committed_cloud.revision;
  trust.save_prepared(interrupted);
  trust.save_outbox({proposal_event, {endpoints[0], endpoints[1]}});
  trust.save_outbox({observation_event, {endpoints[0], endpoints[1]}});

  const AnchorCoordinatorStatus recovered = coordinator.preflight(true);
  expect(recovered.decision.state == AnchorClientState::DegradedReadOnly &&
             trust.load_checkpoint().accepted_head == write.new_head &&
             !trust.prepared_exists() && trust.load_outbox().empty(),
         "an existing OBSERVATION_PUBLISHED journal finalizes without R=2");

  {
    std::lock_guard<std::mutex> lock(anchor->mutex);
    anchor->synchronized_relay_count = 2;
  }
  const AnchorCoordinatorStatus consistent = coordinator.preflight(false);
  expect(consistent.decision.state == AnchorClientState::Consistent &&
             consistent.observed_head == write.new_head,
         "a later R=2 fetch verifies the completed checkpoint");
}
}  // namespace

int main() {
  test_two_clients_catch_up_and_cas_is_append_only();
  test_observation_w2_completes_before_final_read_quorum();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all anchor coordinator integration tests passed\n";
  return 0;
}
