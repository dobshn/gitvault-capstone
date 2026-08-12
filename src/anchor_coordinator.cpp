#include "anchor_coordinator.h"

#include <algorithm>
#include <ctime>
#include <map>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "checkpoint_state_machine.h"
#include "crypto/sha256.h"
#include "util.h"
#include "vault_process_lock.h"

namespace {
template <size_t N>
std::array<uint8_t, N> random_array() {
  const ByteVec bytes = random_bytes(N);
  std::array<uint8_t, N> result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

uint64_t now_seconds() {
  return static_cast<uint64_t>(std::time(nullptr));
}

ReplicaId replica_id(const AnchorChannelConfig& config) {
  const ByteVec decoded = from_hex(config.installation_id);
  if (decoded.size() != 16) {
    throw std::runtime_error("installation_id is not a 128-bit replica ID");
  }
  ReplicaId result{};
  std::copy(decoded.begin(), decoded.end(), result.begin());
  return result;
}

std::vector<NostrTag> genesis_tags(const AnchorChannelConfig& config) {
  return {{"t", to_hex(config.channel_id)}};
}

std::string checkpoint_address(const AnchorChannelConfig& config,
                               const std::string& installation_id) {
  return "gitvault:" + to_hex(config.vault_id) + ":" + installation_id;
}

std::vector<NostrTag> checkpoint_tags(const AnchorChannelConfig& config,
                                      const std::string& installation_id) {
  return {{"t", to_hex(config.channel_id)},
          {"d", checkpoint_address(config, installation_id)}};
}

bool event_equal(const SignedNostrEvent& left,
                 const SignedNostrEvent& right) {
  return serialize_nostr_event_json(left) == serialize_nostr_event_json(right);
}

std::vector<SignedNostrEvent> merge_events(
    const std::vector<SignedNostrEvent>& cached,
    const std::vector<SignedNostrEvent>& fetched) {
  std::map<AnchorHash, SignedNostrEvent> by_id;
  for (const auto& event : cached) by_id.emplace(event.id, event);
  for (const auto& event : fetched) {
    const auto [existing, inserted] = by_id.emplace(event.id, event);
    if (!inserted && !event_equal(existing->second, event)) {
      throw std::runtime_error("different bytes were returned for checkpoint " +
                               to_hex(event.id));
    }
  }
  std::vector<SignedNostrEvent> result;
  for (auto& [id, event] : by_id) {
    (void)id;
    result.push_back(std::move(event));
  }
  return result;
}

std::string publish_failure_detail(const AnchorPublishResult& result) {
  std::ostringstream output;
  for (const auto& endpoint : result.endpoints) {
    if (output.tellp() > 0) output << "; ";
    output << endpoint.endpoint << '=';
    switch (endpoint.status) {
      case AnchorPublishStatus::Accepted: output << "accepted"; break;
      case AnchorPublishStatus::AlreadyPresent: output << "present"; break;
      case AnchorPublishStatus::Rejected: output << "rejected"; break;
      case AnchorPublishStatus::Timeout: output << "timeout"; break;
      case AnchorPublishStatus::TransportError: output << "transport-error"; break;
    }
  }
  return output.str();
}

size_t synchronized_configured_relays(const AnchorFetchResult& fetch,
                                      const AnchorChannelConfig& config) {
  const std::set<std::string> configured(config.relay_urls.begin(),
                                         config.relay_urls.end());
  std::set<std::string> synchronized;
  for (const auto& endpoint : fetch.endpoints) {
    if (endpoint.status == AnchorFetchStatus::Synchronized &&
        configured.count(endpoint.endpoint) != 0) {
      synchronized.insert(endpoint.endpoint);
    }
  }
  return synchronized.size();
}

SignedNostrEvent find_known_event(const AnchorTrustStore& trust,
                                  const AnchorHash& id) {
  std::vector<SignedNostrEvent> known = trust.load_witnesses();
  const auto genesis = trust.load_cached_events();
  known.insert(known.end(), genesis.begin(), genesis.end());
  for (const auto& event : known) {
    if (event.id == id) return event;
  }
  for (const auto& record : trust.load_outbox()) {
    if (record.event.id == id) return record.event;
  }
  throw std::runtime_error("required checkpoint event is missing: " +
                           to_hex(id));
}

bool same_head_state(const VaultHeadState& left,
                     const VaultHeadState& right) {
  return vault_head_states_equal(left, right);
}

std::string clock_relation(const VaultHeadState& left,
                           const VaultHeadState& right) {
  if (left.protocol_epoch != right.protocol_epoch) return "epoch-mismatch";
  return vector_clock_relation_name(
      compare_vector_clocks(left.clock, right.clock));
}
}  // namespace

AnchorCoordinator::AnchorCoordinator(
    ObjectStore& store,
    VaultEngine& engine,
    std::unique_ptr<IAnchorChannel> channel)
    : store_(store),
      engine_(engine),
      channel_(std::move(channel)),
      trust_(store.trust_directory(), engine.trust_mac_key()),
      config_(trust_.load_channel()) {
  if (!channel_) throw std::runtime_error("anchor channel must not be null");
  if (config_.vault_public_key !=
      schnorr_public_key(engine_.identity().signing_secret)) {
    throw std::runtime_error(
        "channel Vault public key does not match wrapped identity");
  }
  if (Sha256::hash(store_.read_local_config_bytes()) != config_.config_hash) {
    throw std::runtime_error(
        "local config bytes do not match the pinned config hash");
  }
  (void)replica_id(config_);
}

AnchorChannelConfig AnchorCoordinator::initialize(
    ObjectStore& store,
    VaultEngine& engine,
    IAnchorChannel& channel,
    const std::vector<std::string>& relay_urls) {
  if (relay_urls.size() != 3 ||
      std::set<std::string>(relay_urls.begin(), relay_urls.end()).size() != 3) {
    throw std::runtime_error("init requires exactly three distinct relays");
  }
  AnchorTrustStore trust(store.trust_directory(), engine.trust_mac_key());
  if (trust.channel_exists() || trust.checkpoint_exists()) {
    throw std::runtime_error("anchor trust state already exists");
  }
  const VersionedBytes cloud = store.read_cloud_head_versioned();
  const VaultHeadState initial = engine.decrypt_head_state(cloud.bytes);
  if (!initial.clock.empty() || initial.protocol_epoch != 0) {
    throw std::runtime_error("initial HEAD must have an empty vector clock");
  }

  AnchorChannelConfig config;
  config.vault_id = random_array<32>();
  config.channel_id = random_array<32>();
  config.vault_public_key =
      schnorr_public_key(engine.identity().signing_secret);
  config.config_hash = Sha256::hash(store.read_local_config_bytes());
  config.installation_id = to_hex(random_bytes(16));
  config.relay_urls = relay_urls;

  VaultGenesisEvent genesis;
  genesis.common.vault_id = config.vault_id;
  genesis.common.operation_id = random_array<16>();
  genesis.common.protocol_epoch = config.protocol_epoch;
  genesis.common.installation_id = config.installation_id;
  genesis.config_hash = config.config_hash;
  genesis.initial_head = initial.head;
  const SignedNostrEvent genesis_event = sign_encrypted_anchor_event(
      genesis, now_seconds(), genesis_tags(config),
      engine.identity().signing_secret);
  config.genesis_event_id = genesis_event.id;
  trust.save_channel(config);

  auto publish_with_quorum = [&](const SignedNostrEvent& event) {
    AnchorOutboxRecord outbox{event, {}};
    trust.save_outbox(outbox);
    const AnchorPublishResult published = channel.publish(event);
    const std::set<std::string> configured(relay_urls.begin(), relay_urls.end());
    for (const auto& endpoint : published.endpoints) {
      if ((endpoint.status == AnchorPublishStatus::Accepted ||
           endpoint.status == AnchorPublishStatus::AlreadyPresent) &&
          configured.count(endpoint.endpoint) != 0) {
        outbox.accepted_endpoints.insert(endpoint.endpoint);
      }
    }
    trust.save_outbox(outbox);
    if (outbox.accepted_endpoints.size() < config.publish_quorum) {
      throw std::runtime_error("initial event did not reach W=2: " +
                               publish_failure_detail(published));
    }
  };

  publish_with_quorum(genesis_event);
  trust.cache_event(genesis_event);
  trust.remove_outbox(genesis_event.id);

  HeadCheckpointEvent checkpoint_payload;
  checkpoint_payload.common.vault_id = config.vault_id;
  checkpoint_payload.common.operation_id = initial.operation_id;
  checkpoint_payload.common.protocol_epoch = initial.protocol_epoch;
  checkpoint_payload.common.installation_id = config.installation_id;
  checkpoint_payload.head = initial.head;
  checkpoint_payload.clock = initial.clock;
  checkpoint_payload.head_envelope_hash = Sha256::hash(cloud.bytes);
  checkpoint_payload.observed_cloud_revision = cloud.revision;
  const uint64_t checkpoint_time = now_seconds();
  const SignedNostrEvent checkpoint_event = sign_encrypted_anchor_event(
      checkpoint_payload, checkpoint_time,
      checkpoint_tags(config, config.installation_id),
      engine.identity().signing_secret);
  publish_with_quorum(checkpoint_event);
  trust.save_witness(replica_id(config), checkpoint_event);
  AnchorCheckpoint checkpoint;
  checkpoint.protocol_epoch = initial.protocol_epoch;
  checkpoint.accepted_head = initial.head;
  checkpoint.accepted_clock = initial.clock;
  checkpoint.head_envelope_hash = Sha256::hash(cloud.bytes);
  checkpoint.tip_event_id = checkpoint_event.id;
  checkpoint.cloud_revision = cloud.revision;
  checkpoint.last_checkpoint_created_at = checkpoint_time;
  trust.save_checkpoint(checkpoint);
  trust.remove_outbox(checkpoint_event.id);
  return config;
}

AnchorStateContext AnchorCoordinator::state_context() const {
  AnchorStateContext context;
  context.trusted_public_key = config_.vault_public_key;
  context.expected_vault_id = config_.vault_id;
  context.expected_config_hash = config_.config_hash;
  context.expected_channel_tag = to_hex(config_.channel_id);
  context.expected_protocol_epoch = config_.protocol_epoch;
  context.genesis_event_id = config_.genesis_event_id;
  context.verify_commit_parent =
      [this](const AnchorHash& commit, const AnchorHash& parent) {
        return engine_.verify_commit_parent(commit, parent);
      };
  context.is_commit_ancestor =
      [this](const AnchorHash& ancestor, const AnchorHash& descendant) {
        return engine_.is_commit_ancestor(ancestor, descendant);
      };
  context.decode_event = [this](const SignedNostrEvent& event) {
    return verify_decrypt_anchor_event(
        event, config_.vault_public_key, engine_.identity().signing_secret);
  };
  return context;
}

void AnchorCoordinator::replay_outbox() {
  const std::set<std::string> configured(config_.relay_urls.begin(),
                                         config_.relay_urls.end());
  for (auto record : trust_.load_outbox()) {
    const AnchorPublishResult result = channel_->publish(record.event);
    for (const auto& endpoint : result.endpoints) {
      if ((endpoint.status == AnchorPublishStatus::Accepted ||
           endpoint.status == AnchorPublishStatus::AlreadyPresent) &&
          configured.count(endpoint.endpoint) != 0) {
        record.accepted_endpoints.insert(endpoint.endpoint);
      }
    }
    trust_.save_outbox(record);
  }
}

AnchorPublishResult AnchorCoordinator::ensure_published(
    const SignedNostrEvent& event) {
  AnchorOutboxRecord record{event, {}};
  for (const auto& existing : trust_.load_outbox()) {
    if (existing.event.id == event.id) {
      if (!event_equal(existing.event, event)) {
        throw std::runtime_error("outbox event ID conflict");
      }
      record = existing;
      break;
    }
  }
  trust_.save_outbox(record);
  const AnchorPublishResult result = channel_->publish(event);
  const std::set<std::string> configured(config_.relay_urls.begin(),
                                         config_.relay_urls.end());
  for (const auto& endpoint : result.endpoints) {
    if ((endpoint.status == AnchorPublishStatus::Accepted ||
         endpoint.status == AnchorPublishStatus::AlreadyPresent) &&
        configured.count(endpoint.endpoint) != 0) {
      record.accepted_endpoints.insert(endpoint.endpoint);
    }
  }
  trust_.save_outbox(record);
  if (record.accepted_endpoints.size() < config_.publish_quorum) {
    throw std::runtime_error("checkpoint did not reach W=2: " +
                             publish_failure_detail(result));
  }
  return result;
}

SignedNostrEvent AnchorCoordinator::make_checkpoint(
    const VaultHeadState& head,
    const ByteVec& head_envelope,
    const std::string& cloud_revision) {
  const AnchorCheckpoint local = trust_.load_checkpoint();
  HeadCheckpointEvent checkpoint;
  checkpoint.common.vault_id = config_.vault_id;
  checkpoint.common.operation_id = head.operation_id;
  checkpoint.common.protocol_epoch = head.protocol_epoch;
  checkpoint.common.installation_id = config_.installation_id;
  checkpoint.head = head.head;
  checkpoint.clock = head.clock;
  checkpoint.head_envelope_hash = Sha256::hash(head_envelope);
  checkpoint.observed_cloud_revision = cloud_revision;
  if (local.last_checkpoint_created_at ==
      std::numeric_limits<uint64_t>::max()) {
    throw std::runtime_error("checkpoint timestamp overflow");
  }
  const uint64_t created_at =
      std::max(now_seconds(), local.last_checkpoint_created_at + 1);
  return sign_encrypted_anchor_event(
      checkpoint, created_at,
      checkpoint_tags(config_, config_.installation_id),
      engine_.identity().signing_secret);
}

void AnchorCoordinator::publish_and_adopt_checkpoint(
    const VaultHeadState& head,
    const VersionedBytes& cloud) {
  const SignedNostrEvent checkpoint =
      make_checkpoint(head, cloud.bytes, cloud.revision);
  trust_.save_outbox({checkpoint, {}});
  (void)ensure_published(checkpoint);
  trust_.save_witness(replica_id(config_), checkpoint);
  adopt_published_observation(head.head, checkpoint.id, cloud);
  trust_.remove_outbox(checkpoint.id);
}

AnchorCoordinatorStatus AnchorCoordinator::evaluate_current(
    bool read_only_operation,
    bool recover) {
  if (!trust_.checkpoint_exists()) {
    throw std::runtime_error(
        "vector checkpoint is missing; initialize or import the Vault again");
  }
  if (recover) replay_outbox();

  AnchorCoordinatorStatus status;
  const AnchorCheckpoint checkpoint = trust_.load_checkpoint();
  const VersionedBytes cloud = store_.read_cloud_head_versioned();
  status.cloud_head_bytes = cloud.bytes;
  status.cloud_revision = cloud.revision;
  status.cloud_head_state = engine_.decrypt_head_state(cloud.bytes);
  status.local_head_state =
      engine_.decrypt_head_state(store_.read_local_head());
  status.cloud_head = status.cloud_head_state.head;
  status.local_head = status.local_head_state.head;

  AnchorChannelQuery query;
  query.author = config_.vault_public_key;
  query.kind = kGitVaultCheckpointEventKind;
  query.required_tags = {{"t", to_hex(config_.channel_id)}};
  status.relay_fetch = channel_->fetch(query);
  const std::vector<SignedNostrEvent> events = merge_events(
      trust_.load_witnesses(), status.relay_fetch.events);

  CheckpointStateInput input;
  input.witness_events = events;
  input.local_checkpoint = checkpoint;
  input.local_head = status.local_head_state;
  input.cloud_head = status.cloud_head_state;
  input.cloud_head_envelope_hash = Sha256::hash(cloud.bytes);
  input.channel_synchronized =
      synchronized_configured_relays(status.relay_fetch, config_) >=
      config_.read_quorum;
  input.read_only_operation = read_only_operation;
  input.prepared_write_exists = trust_.prepared_exists();
  status.decision = evaluate_checkpoint_state(state_context(), input);
  status.observed_head = status.decision.verified_tip;
  status.local_cloud_relation =
      clock_relation(status.local_head_state, status.cloud_head_state);
  VaultHeadState observed;
  observed.protocol_epoch = config_.protocol_epoch;
  observed.head = status.decision.verified_tip;
  observed.clock = status.decision.verified_clock;
  status.cloud_observed_relation =
      clock_relation(status.cloud_head_state, observed);
  status.local_observed_relation =
      clock_relation(status.local_head_state, observed);
  if (trust_.prepared_exists()) status.prepared = trust_.load_prepared();
  status.pending_outbox = trust_.load_outbox();

  if (input.channel_synchronized &&
      status.decision.state != AnchorClientState::Forked) {
    const std::set<AnchorHash> valid(
        status.decision.valid_observation_event_ids.begin(),
        status.decision.valid_observation_event_ids.end());
    struct LatestWitness {
      VectorClock clock;
      SignedNostrEvent event;
    };
    std::map<ReplicaId, LatestWitness> latest_by_replica;
    for (const auto& event : events) {
      if (valid.count(event.id) == 0) continue;
      const AnchorEventPayload decoded = state_context().decode_event(event);
      const auto* witnessed = std::get_if<HeadCheckpointEvent>(&decoded);
      if (witnessed == nullptr) continue;
      const ByteVec id_bytes = from_hex(witnessed->common.installation_id);
      ReplicaId id{};
      std::copy(id_bytes.begin(), id_bytes.end(), id.begin());
      const auto found = latest_by_replica.find(id);
      if (found == latest_by_replica.end()) {
        latest_by_replica.emplace(
            id, LatestWitness{witnessed->clock, event});
        continue;
      }
      const VectorClockRelation relation =
          compare_vector_clocks(found->second.clock, witnessed->clock);
      if (relation == VectorClockRelation::Before ||
          (relation == VectorClockRelation::Equal &&
           (found->second.event.created_at < event.created_at ||
            (found->second.event.created_at == event.created_at &&
             event.id < found->second.event.id)))) {
        found->second = LatestWitness{witnessed->clock, event};
      }
    }
    for (const auto& [id, latest] : latest_by_replica) {
      trust_.save_witness(id, latest.event);
    }
  }

  if (!recover) return status;
  if (status.decision.state == AnchorClientState::Forked ||
      status.decision.state == AnchorClientState::RollbackDetected) {
    return status;
  }
  if (status.prepared.has_value()) {
    return resume_prepared(*status.prepared, status, read_only_operation);
  }
  if (status.decision.state == AnchorClientState::ObservationRequired) {
    if (!engine_.is_commit_ancestor(checkpoint.accepted_head,
                                    status.cloud_head_state.head)) {
      throw std::runtime_error(
          "comparable cloud clock does not have the trusted Commit as ancestor");
    }
    publish_and_adopt_checkpoint(status.cloud_head_state, cloud);
    return evaluate_current(read_only_operation, false);
  }
  if (status.decision.state == AnchorClientState::LocalCatchUp) {
    if (!engine_.is_commit_ancestor(checkpoint.accepted_head,
                                    status.cloud_head_state.head)) {
      throw std::runtime_error(
          "checkpoint catch-up failed Commit ancestry verification");
    }
    adopt_checkpoint(status);
    status.local_head = status.cloud_head;
    status.local_head_state = status.cloud_head_state;
  } else if (status.decision.state == AnchorClientState::Consistent) {
    adopt_checkpoint(status);
  }
  return status;
}

void AnchorCoordinator::adopt_checkpoint(
    const AnchorCoordinatorStatus& current) {
  if (current.cloud_head_state.clock != current.decision.verified_clock ||
      current.cloud_head_state.head != current.decision.verified_tip) {
    throw std::runtime_error(
        "refusing to adopt a cloud HEAD without an exact signed checkpoint");
  }
  store_.write_local_head(current.cloud_head_bytes);
  AnchorCheckpoint checkpoint = trust_.load_checkpoint();
  checkpoint.protocol_epoch = current.cloud_head_state.protocol_epoch;
  checkpoint.accepted_head = current.cloud_head_state.head;
  checkpoint.accepted_clock = current.cloud_head_state.clock;
  checkpoint.head_envelope_hash = Sha256::hash(current.cloud_head_bytes);
  checkpoint.tip_event_id = current.decision.verified_tip_event_id;
  checkpoint.cloud_revision = current.cloud_revision;
  trust_.save_checkpoint(checkpoint);
}

void AnchorCoordinator::adopt_published_observation(
    const AnchorHash& head,
    const AnchorHash& checkpoint_event_id,
    const VersionedBytes& cloud) {
  const VaultHeadState state = engine_.decrypt_head_state(cloud.bytes);
  if (state.head != head) {
    throw std::runtime_error(
        "refusing to checkpoint a different Dropbox HEAD");
  }
  const SignedNostrEvent event =
      find_known_event(trust_, checkpoint_event_id);
  const AnchorEventPayload decoded = state_context().decode_event(event);
  const auto* checkpoint_event = std::get_if<HeadCheckpointEvent>(&decoded);
  if (checkpoint_event == nullptr || checkpoint_event->head != state.head ||
      checkpoint_event->clock != state.clock ||
      checkpoint_event->head_envelope_hash != Sha256::hash(cloud.bytes)) {
    throw std::runtime_error("signed checkpoint does not match Dropbox HEAD");
  }
  store_.write_local_head(cloud.bytes);
  AnchorCheckpoint checkpoint;
  checkpoint.protocol_epoch = state.protocol_epoch;
  checkpoint.accepted_head = state.head;
  checkpoint.accepted_clock = state.clock;
  checkpoint.head_envelope_hash = Sha256::hash(cloud.bytes);
  checkpoint.tip_event_id = checkpoint_event_id;
  checkpoint.cloud_revision = cloud.revision;
  checkpoint.last_checkpoint_created_at = event.created_at;
  trust_.save_checkpoint(checkpoint);
}

void AnchorCoordinator::finalize_prepared(
    const PreparedWriteRecord& prepared) {
  if (prepared.proposal_event_id.has_value()) {
    trust_.remove_outbox(*prepared.proposal_event_id);
  }
  if (prepared.observation_event_id.has_value()) {
    trust_.remove_outbox(*prepared.observation_event_id);
  }
  trust_.clear_prepared();
}

AnchorCoordinatorStatus AnchorCoordinator::resume_prepared(
    PreparedWriteRecord prepared,
    const AnchorCoordinatorStatus& current,
    bool read_only_operation) {
  (void)current;
  VaultHeadState expected_previous;
  expected_previous.protocol_epoch = prepared.protocol_epoch;
  expected_previous.head = prepared.previous_head;
  expected_previous.clock = prepared.previous_clock;
  VaultHeadState expected_new;
  expected_new.protocol_epoch = prepared.protocol_epoch;
  expected_new.head = prepared.new_head;
  expected_new.clock = prepared.new_clock;
  expected_new.writer_replica_id = replica_id(config_);
  expected_new.operation_id = prepared.operation_id;
  const VaultHeadState journal_state =
      engine_.decrypt_head_state(prepared.encrypted_head_bytes);
  if (!same_head_state(journal_state, expected_new)) {
    throw std::runtime_error("prepared encrypted HEAD does not match its journal");
  }

  VersionedBytes cloud = store_.read_cloud_head_versioned();
  VaultHeadState cloud_state = engine_.decrypt_head_state(cloud.bytes);
  if (cloud_state.head == expected_previous.head &&
      cloud_state.clock == expected_previous.clock &&
      cloud_state.protocol_epoch == expected_previous.protocol_epoch) {
    const ConditionalWriteResult updated = store_.compare_exchange_cloud_head(
        prepared.encrypted_head_bytes, prepared.cloud_revision);
    if (updated.status == ConditionalWriteStatus::Conflict) {
      trust_.clear_prepared();
      throw std::runtime_error(
          "Dropbox HEAD CAS conflict; no signed checkpoint was created; "
          "reload and retry the command");
    }
    cloud = store_.read_cloud_head_versioned();
    if (!updated.revision.empty() && updated.revision != cloud.revision) {
      throw std::runtime_error(
          "Dropbox CAS response revision differs from exact readback revision");
    }
    cloud_state = engine_.decrypt_head_state(cloud.bytes);
  }
  if (!same_head_state(cloud_state, expected_new) ||
      !constant_time_equal(cloud.bytes, prepared.encrypted_head_bytes)) {
    throw std::runtime_error(
        "Dropbox CAS readback does not exactly match the prepared HEAD bytes");
  }
  prepared.cloud_revision = cloud.revision;
  prepared.phase = PreparedWritePhase::HeadUpdated;
  trust_.save_prepared(prepared);

  SignedNostrEvent checkpoint;
  if (!prepared.observation_event_id.has_value()) {
    checkpoint = make_checkpoint(cloud_state, cloud.bytes, cloud.revision);
    trust_.save_outbox({checkpoint, {}});
    prepared.observation_event_id = checkpoint.id;
    trust_.save_prepared(prepared);
  } else {
    checkpoint = find_known_event(trust_, *prepared.observation_event_id);
  }
  (void)ensure_published(checkpoint);
  trust_.save_witness(replica_id(config_), checkpoint);
  prepared.phase = PreparedWritePhase::ObservationPublished;
  trust_.save_prepared(prepared);
  adopt_published_observation(prepared.new_head, checkpoint.id, cloud);
  finalize_prepared(prepared);
  return evaluate_current(read_only_operation, false);
}

AnchorCoordinatorStatus AnchorCoordinator::preflight(
    bool read_only_operation) {
  VaultProcessLock lock(trust_.trust_directory() / "write.lock");
  return evaluate_current(read_only_operation, true);
}

PreparedVaultWrite AnchorCoordinator::execute_write(
    const std::function<PreparedVaultWrite(const AnchorHash&)>& prepare) {
  VaultProcessLock lock(trust_.trust_directory() / "write.lock");
  AnchorCoordinatorStatus status = evaluate_current(false, true);
  if (status.decision.state != AnchorClientState::Consistent) {
    throw std::runtime_error(
        std::string("write requires CONSISTENT state; current state is ") +
        anchor_client_state_name(status.decision.state) + " (" +
        anchor_state_reason_name(status.decision.reason) + "): " +
        status.decision.detail);
  }
  const PreparedVaultWrite write = prepare(status.cloud_head);
  if (!engine_.verify_commit_parent(write.new_head, status.cloud_head)) {
    throw std::runtime_error("prepared Commit does not use the CAS base as parent");
  }

  PreparedWriteRecord journal;
  journal.protocol_epoch = status.cloud_head_state.protocol_epoch;
  journal.operation_id = write.operation_id;
  journal.previous_head = status.cloud_head;
  journal.new_head = write.new_head;
  journal.previous_clock = status.cloud_head_state.clock;
  journal.new_clock = increment_vector_clock(
      status.cloud_head_state.clock, replica_id(config_));
  VaultHeadState new_state;
  new_state.protocol_epoch = journal.protocol_epoch;
  new_state.head = journal.new_head;
  new_state.clock = journal.new_clock;
  new_state.writer_replica_id = replica_id(config_);
  new_state.operation_id = journal.operation_id;
  journal.encrypted_head_bytes = engine_.encrypt_head_state(new_state);
  journal.phase = PreparedWritePhase::ObjectsPrepared;
  journal.cloud_revision = status.cloud_revision;
  trust_.save_prepared(journal);

  const AnchorCoordinatorStatus completed = evaluate_current(false, true);
  const AnchorCheckpoint checkpoint = trust_.load_checkpoint();
  if (checkpoint.accepted_head != write.new_head ||
      completed.cloud_head != write.new_head || trust_.prepared_exists()) {
    throw std::runtime_error("write did not reach its signed vector checkpoint");
  }
  return write;
}

const AnchorChannelConfig& AnchorCoordinator::config() const {
  return config_;
}
