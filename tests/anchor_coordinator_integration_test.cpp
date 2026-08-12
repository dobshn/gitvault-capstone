#include "API.h"
#include "anchor_coordinator.h"
#include "anchor_trust_store.h"
#include "crypto/sha256.h"
#include "object_store.h"
#include "util.h"
#include "vault_engine.h"

#include <algorithm>
#include <filesystem>
#include <iostream>
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

template <size_t N>
std::array<uint8_t, N> filled(uint8_t value) {
  std::array<uint8_t, N> result{};
  result.fill(value);
  return result;
}

struct TempDirectory {
  std::filesystem::path path = std::filesystem::temp_directory_path() /
      ("gitvault-vector-coordinator-test-" + to_hex(random_bytes(8)));
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
  bool conflict_next_cas = false;
  size_t remove_calls = 0;
};

class FakeCloudApi final : public API {
public:
  explicit FakeCloudApi(std::shared_ptr<SharedCloud> cloud)
      : cloud_(std::move(cloud)) {}

  void init(std::string, std::string) override {}
  void fetch(std::string, std::string) override {}
  bool destroy(std::string, std::string) override { return true; }

  void put(std::string_view path, const ByteVec& data, bool overwrite) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    const std::string key(path);
    if (!overwrite && cloud_->files.count(key) != 0) {
      throw std::runtime_error("fake add conflict");
    }
    cloud_->files[key] = {data, revision()};
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
      std::string_view path, const ByteVec& data,
      std::string_view expected_revision) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    if (cloud_->conflict_next_cas) {
      cloud_->conflict_next_cas = false;
      return {ConditionalWriteStatus::Conflict, {}};
    }
    const auto found = cloud_->files.find(std::string(path));
    if (found == cloud_->files.end() ||
        found->second.revision != expected_revision) {
      return {ConditionalWriteStatus::Conflict, {}};
    }
    const std::string next = revision();
    found->second = {data, next};
    return {ConditionalWriteStatus::Updated, next};
  }

  ConditionalWriteResult put_if_absent(
      std::string_view path, const ByteVec& data) const override {
    std::lock_guard<std::mutex> lock(cloud_->mutex);
    const std::string key(path);
    if (cloud_->files.count(key) != 0) {
      return {ConditionalWriteStatus::Conflict, {}};
    }
    const std::string next = revision();
    cloud_->files[key] = {data, next};
    return {ConditionalWriteStatus::Updated, next};
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
  std::string revision() const {
    return "rev-" + std::to_string(cloud_->next_revision++);
  }
  std::shared_ptr<SharedCloud> cloud_;
};

struct SharedAnchor {
  std::mutex mutex;
  std::map<AnchorHash, SignedNostrEvent> immutable;
  std::map<std::string, SignedNostrEvent> addressable;
  size_t accepted_relay_count = 3;
  size_t synchronized_relay_count = 3;
};

std::string d_tag(const SignedNostrEvent& event) {
  for (const auto& tag : event.tags) {
    if (tag.size() == 2 && tag[0] == "d") return tag[1];
  }
  return {};
}

class ThreeRelayChannel final : public IAnchorChannel {
public:
  ThreeRelayChannel(std::shared_ptr<SharedAnchor> anchor,
                    std::vector<std::string> endpoints)
      : anchor_(std::move(anchor)), endpoints_(std::move(endpoints)) {}

  AnchorPublishResult publish(const SignedNostrEvent& event) override {
    {
      std::lock_guard<std::mutex> lock(anchor_->mutex);
      if (event.kind == kGitVaultCheckpointEventKind) {
        const std::string address = d_tag(event);
        if (address.empty()) throw std::runtime_error("checkpoint has no d tag");
        const auto found = anchor_->addressable.find(address);
        if (found == anchor_->addressable.end() ||
            found->second.created_at < event.created_at ||
            (found->second.created_at == event.created_at &&
             event.id < found->second.id)) {
          anchor_->addressable[address] = event;
        }
      } else {
        anchor_->immutable.emplace(event.id, event);
      }
    }
    AnchorPublishResult result;
    for (size_t index = 0; index < endpoints_.size(); ++index) {
      result.endpoints.push_back(
          {endpoints_[index], event.id,
           index < anchor_->accepted_relay_count
               ? AnchorPublishStatus::Accepted
               : AnchorPublishStatus::Timeout,
           {}, 0});
    }
    return result;
  }

  AnchorFetchResult fetch(const AnchorChannelQuery& query) const override {
    AnchorFetchResult result;
    std::lock_guard<std::mutex> lock(anchor_->mutex);
    auto include = [&](const SignedNostrEvent& event) {
      if (query.author.has_value() && event.public_key != *query.author) return;
      if (query.kind.has_value() && event.kind != *query.kind) return;
      for (const auto& tag : query.required_tags) {
        if (std::find(event.tags.begin(), event.tags.end(), tag) ==
            event.tags.end()) return;
      }
      result.events.push_back(event);
    };
    for (const auto& [id, event] : anchor_->immutable) {
      (void)id;
      include(event);
    }
    for (const auto& [address, event] : anchor_->addressable) {
      (void)address;
      include(event);
    }
    for (size_t index = 0; index < endpoints_.size(); ++index) {
      result.endpoints.push_back(
          {endpoints_[index],
           index < anchor_->synchronized_relay_count
               ? AnchorFetchStatus::Synchronized
               : AnchorFetchStatus::TransportError,
           {}, 0});
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
  AnchorTrustStore source(source_store.trust_directory(),
                          source_engine.trust_mac_key());
  target_store.write_local_config_bytes(source_store.read_local_config_bytes());
  target_store.save_vault_identity(source_store.load_vault_identity());
  VaultEngine target_engine(target_store, password);
  AnchorTrustStore target(target_store.trust_directory(),
                          target_engine.trust_mac_key());
  AnchorChannelConfig channel = source.load_channel();
  channel.installation_id = std::string(32, 'b');
  target.save_channel(channel);
  target.save_checkpoint(source.load_checkpoint());
  for (const auto& event : source.load_cached_events()) target.cache_event(event);
  for (const auto& event : source.load_witnesses()) {
    const AnchorEventPayload payload = verify_decrypt_anchor_event(
        event, channel.vault_public_key,
        target_engine.identity().signing_secret);
    const auto& checkpoint = std::get<HeadCheckpointEvent>(payload);
    const ByteVec bytes = from_hex(checkpoint.common.installation_id);
    ReplicaId id{};
    std::copy(bytes.begin(), bytes.end(), id.begin());
    target.save_witness(id, event);
  }
  target_store.write_local_head(source_store.read_cloud_head_versioned().bytes);
}

struct Fixture {
  TempDirectory temp;
  std::string password = "integration-password";
  std::vector<std::string> endpoints = {
      "wss://relay-one.invalid", "wss://relay-two.invalid",
      "wss://relay-three.invalid"};
  std::shared_ptr<SharedCloud> cloud = std::make_shared<SharedCloud>();
  std::shared_ptr<SharedAnchor> anchor = std::make_shared<SharedAnchor>();
  ObjectStore store_a{std::make_unique<FakeCloudApi>(cloud), temp.path / "a"};

  Fixture() { store_a.init("token", "vault"); }
};

void test_two_clients_cas_and_frozen_components() {
  Fixture fixture;
  VaultEngine engine_a(fixture.store_a, fixture.password, true);
  const AnchorHash initial = engine_a.init_vault();
  ThreeRelayChannel init_channel(fixture.anchor, fixture.endpoints);
  (void)AnchorCoordinator::initialize(
      fixture.store_a, engine_a, init_channel, fixture.endpoints);

  ObjectStore store_b(std::make_unique<FakeCloudApi>(fixture.cloud),
                      fixture.temp.path / "b");
  store_b.fetch("token", "vault");
  install_second_client(fixture.store_a, engine_a, store_b, fixture.password);
  VaultEngine engine_b(store_b, fixture.password);
  AnchorCoordinator coordinator_a(
      fixture.store_a, engine_a,
      std::make_unique<ThreeRelayChannel>(fixture.anchor, fixture.endpoints));
  AnchorCoordinator coordinator_b(
      store_b, engine_b,
      std::make_unique<ThreeRelayChannel>(fixture.anchor, fixture.endpoints));

  const PreparedVaultWrite first = coordinator_a.execute_write(
      [&](const AnchorHash& base) {
        return engine_a.prepare_mkdir("from-a", base);
      });
  expect(first.previous_head == initial,
         "first replica writes from the empty vector clock");
  const VaultHeadState after_a = engine_a.decrypt_head_state(
      fixture.store_a.read_cloud_head_versioned().bytes);
  expect(after_a.clock.size() == 1,
         "first CAS adds exactly one replica component");

  const AnchorCoordinatorStatus caught_up = coordinator_b.preflight(false);
  expect(caught_up.decision.state == AnchorClientState::LocalCatchUp,
         "second replica safely catches up using a comparable checkpoint");
  expect(coordinator_b.preflight(false).decision.state ==
             AnchorClientState::Consistent,
         "second replica becomes consistent after catch-up");

  (void)coordinator_b.execute_write([&](const AnchorHash& base) {
    return engine_b.prepare_mkdir("from-b", base);
  });
  const VaultHeadState after_b = engine_b.decrypt_head_state(
      store_b.read_cloud_head_versioned().bytes);
  expect(after_b.clock.size() == 2,
         "a newly writing replica adds its own vector component");

  (void)coordinator_a.preflight(false);
  (void)coordinator_a.preflight(false);
  const size_t before_conflict = object_count(fixture.cloud);
  {
    std::lock_guard<std::mutex> lock(fixture.cloud->mutex);
    fixture.cloud->conflict_next_cas = true;
  }
  bool conflict = false;
  try {
    (void)coordinator_a.execute_write([&](const AnchorHash& base) {
      return engine_a.prepare_mkdir("losing-write", base);
    });
  } catch (const std::runtime_error& error) {
    conflict = std::string(error.what()).find("CAS conflict") !=
               std::string::npos;
  }
  expect(conflict, "a stale Dropbox revision produces a CAS conflict");
  expect(object_count(fixture.cloud) > before_conflict &&
             fixture.cloud->remove_calls == 0,
         "CAS failure retains immutable prepared objects");

  (void)coordinator_a.execute_write([&](const AnchorHash& base) {
    return engine_a.prepare_mkdir("after-b-retired", base);
  });
  const VaultHeadState final_state = engine_a.decrypt_head_state(
      fixture.store_a.read_cloud_head_versioned().bytes);
  expect(final_state.clock.size() == 2,
         "an inactive replica component remains as a frozen tombstone");
  expect(fixture.anchor->addressable.size() == 2,
         "Nostr retains one latest addressable checkpoint per replica");
  const auto witness_count = [](const std::filesystem::path& directory) {
    size_t result = 0;
    for (const auto& item : std::filesystem::directory_iterator(directory)) {
      if (item.is_regular_file() && item.path().extension() == ".json") ++result;
    }
    return result;
  };
  expect(witness_count(fixture.store_a.trust_directory() / "witnesses") == 2,
         "local trust storage keeps only one latest witness per replica");
}

void test_checkpoint_publish_recovery_and_degraded_read() {
  Fixture fixture;
  VaultEngine engine(fixture.store_a, fixture.password, true);
  (void)engine.init_vault();
  ThreeRelayChannel init_channel(fixture.anchor, fixture.endpoints);
  (void)AnchorCoordinator::initialize(
      fixture.store_a, engine, init_channel, fixture.endpoints);
  AnchorCoordinator coordinator(
      fixture.store_a, engine,
      std::make_unique<ThreeRelayChannel>(fixture.anchor, fixture.endpoints));

  fixture.anchor->accepted_relay_count = 1;
  bool quorum_failure = false;
  try {
    (void)coordinator.execute_write([&](const AnchorHash& base) {
      return engine.prepare_mkdir("resume-after-w1", base);
    });
  } catch (const std::runtime_error& error) {
    quorum_failure = std::string(error.what()).find("W=2") != std::string::npos;
  }
  AnchorTrustStore trust(fixture.store_a.trust_directory(),
                         engine.trust_mac_key());
  expect(quorum_failure && trust.prepared_exists() &&
             !trust.load_outbox().empty(),
         "W=1 after CAS leaves a durable journal and checkpoint outbox");

  fixture.anchor->accepted_relay_count = 3;
  const AnchorCoordinatorStatus recovered = coordinator.preflight(false);
  expect(!trust.prepared_exists() && trust.load_outbox().empty() &&
             recovered.cloud_head == trust.load_checkpoint().accepted_head,
         "the next preflight republishes and finalizes the exact CAS result");

  fixture.anchor->synchronized_relay_count = 1;
  const AnchorCoordinatorStatus degraded = coordinator.preflight(true);
  expect(degraded.decision.state == AnchorClientState::DegradedReadOnly,
         "R<2 permits only a local/cloud-equal degraded read");
}

void test_incompatible_signed_checkpoints_detect_fork() {
  Fixture fixture;
  VaultEngine engine(fixture.store_a, fixture.password, true);
  (void)engine.init_vault();
  ThreeRelayChannel channel(fixture.anchor, fixture.endpoints);
  const AnchorChannelConfig config = AnchorCoordinator::initialize(
      fixture.store_a, engine, channel, fixture.endpoints);

  auto publish_fork = [&](const std::string& installation,
                          const ReplicaId& replica,
                          const AnchorHash& head,
                          uint64_t created_at) {
    HeadCheckpointEvent payload;
    payload.common.vault_id = config.vault_id;
    payload.common.operation_id = filled<16>(static_cast<uint8_t>(created_at));
    payload.common.protocol_epoch = config.protocol_epoch;
    payload.common.installation_id = installation;
    payload.head = head;
    payload.clock[replica] = 1;
    payload.head_envelope_hash = filled<32>(static_cast<uint8_t>(created_at));
    payload.observed_cloud_revision = "malicious-cas-view";
    const SignedNostrEvent event = sign_encrypted_anchor_event(
        payload, created_at,
        {{"t", to_hex(config.channel_id)},
         {"d", "gitvault:" + to_hex(config.vault_id) + ":" + installation}},
        engine.identity().signing_secret);
    (void)channel.publish(event);
  };

  publish_fork(std::string(32, 'a'), filled<16>(0xaa), filled<32>(0x41), 500);
  publish_fork(std::string(32, 'b'), filled<16>(0xbb), filled<32>(0x42), 501);

  AnchorCoordinator coordinator(
      fixture.store_a, engine,
      std::make_unique<ThreeRelayChannel>(fixture.anchor, fixture.endpoints));
  const AnchorCoordinatorStatus status = coordinator.preflight(false);
  expect(status.decision.state == AnchorClientState::Forked &&
             status.decision.reason ==
                 AnchorStateReason::DivergentObservedBranches,
         "incompatible signed vector checkpoints expose a CAS fork");
}
}  // namespace

int main() {
  test_two_clients_cas_and_frozen_components();
  test_checkpoint_publish_recovery_and_degraded_read();
  test_incompatible_signed_checkpoints_detect_fork();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all vector checkpoint coordinator tests passed\n";
  return 0;
}
