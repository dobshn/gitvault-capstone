#include "anchor_coordinator.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "crypto/sha256.h"
#include "util.h"

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

std::vector<NostrTag> channel_tags(const AnchorChannelConfig& config) {
  return {{"t", to_hex(config.channel_id)}};
}

bool event_equal(const SignedNostrEvent& left,
                 const SignedNostrEvent& right) {
  return serialize_nostr_event_json(left) == serialize_nostr_event_json(right);
}

std::vector<SignedNostrEvent> merge_events(
    const std::vector<SignedNostrEvent>& cached,
    const std::vector<SignedNostrEvent>& fetched) {
  std::map<AnchorHash, SignedNostrEvent> by_id;
  for (const auto& event : cached) {
    by_id.emplace(event.id, event);
  }
  for (const auto& event : fetched) {
    const auto [existing, inserted] = by_id.emplace(event.id, event);
    if (!inserted && !event_equal(existing->second, event)) {
      throw std::runtime_error(
          "cached and fetched event bytes conflict for ID " +
          to_hex(event.id));
    }
  }
  std::vector<SignedNostrEvent> result;
  result.reserve(by_id.size());
  for (auto& [id, event] : by_id) {
    (void)id;
    result.push_back(std::move(event));
  }
  return result;
}

PreparedHeadTransition transition(const PreparedWriteRecord& prepared) {
  return {prepared.operation_id, prepared.previous_head, prepared.new_head};
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
    if (!endpoint.message.empty()) output << '(' << endpoint.message << ')';
  }
  return output.str();
}

size_t synchronized_configured_relays(
    const AnchorFetchResult& fetch,
    const AnchorChannelConfig& config) {
  const std::set<std::string> configured(
      config.relay_urls.begin(), config.relay_urls.end());
  std::set<std::string> synchronized;
  for (const auto& endpoint : fetch.endpoints) {
    if (endpoint.status == AnchorFetchStatus::Synchronized &&
        configured.count(endpoint.endpoint) != 0) {
      synchronized.insert(endpoint.endpoint);
    }
  }
  return synchronized.size();
}

const SignedNostrEvent& find_event(
    const std::vector<SignedNostrEvent>& events,
    const AnchorHash& id) {
  const auto found = std::find_if(events.begin(), events.end(),
                                  [&](const SignedNostrEvent& event) {
                                    return event.id == id;
                                  });
  if (found == events.end()) {
    throw std::runtime_error("required anchor event is missing: " +
                             to_hex(id));
  }
  return *found;
}

SignedNostrEvent find_known_event(const AnchorTrustStore& trust,
                                  const AnchorHash& id) {
  const auto cached = trust.load_cached_events();
  const auto cached_event = std::find_if(
      cached.begin(), cached.end(),
      [&](const SignedNostrEvent& event) { return event.id == id; });
  if (cached_event != cached.end()) return *cached_event;
  const auto outbox = trust.load_outbox();
  const auto pending = std::find_if(
      outbox.begin(), outbox.end(),
      [&](const AnchorOutboxRecord& record) { return record.event.id == id; });
  if (pending != outbox.end()) return pending->event;
  throw std::runtime_error("required anchor event is missing: " + to_hex(id));
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
  if (!channel_) {
    throw std::runtime_error("anchor channel must not be null");
  }
  if (config_.vault_public_key !=
      schnorr_public_key(engine_.identity().signing_secret)) {
    throw std::runtime_error(
        "channel Vault public key does not match wrapped identity");
  }
  const ByteVec config_bytes = store_.read_local_config_bytes();
  if (Sha256::hash(config_bytes) != config_.config_hash) {
    throw std::runtime_error(
        "local config bytes do not match the pinned Genesis config hash");
  }
  if (config_.read_quorum == 3) {
    config_.read_quorum = 2;
    trust_.save_channel(config_);
  }
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
  const AnchorHash initial_head = engine.decrypt_head(cloud.bytes);
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
  genesis.initial_head = initial_head;
  const SignedNostrEvent event = sign_encrypted_anchor_event(
      genesis, now_seconds(), channel_tags(config),
      engine.identity().signing_secret);
  config.genesis_event_id = event.id;

  trust.save_channel(config);
  AnchorOutboxRecord outbox{event, {}};
  trust.save_outbox(outbox);
  const AnchorPublishResult published = channel.publish(event);
  const std::set<std::string> configured_relays(
      config.relay_urls.begin(), config.relay_urls.end());
  for (const auto& endpoint : published.endpoints) {
    if (endpoint.status == AnchorPublishStatus::Accepted ||
        endpoint.status == AnchorPublishStatus::AlreadyPresent) {
      if (configured_relays.count(endpoint.endpoint) == 0) continue;
      outbox.accepted_endpoints.insert(endpoint.endpoint);
    }
  }
  trust.save_outbox(outbox);
  if (outbox.accepted_endpoints.size() < config.publish_quorum) {
    throw std::runtime_error(
        "Genesis did not reach the W=2 publish policy: " +
        publish_failure_detail(published));
  }
  trust.cache_event(event);
  trust.save_checkpoint(
      {1, initial_head, event.id, cloud.revision});
  trust.remove_outbox(event.id);
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
  const std::set<std::string> configured_relays(
      config_.relay_urls.begin(), config_.relay_urls.end());
  for (auto record : trust_.load_outbox()) {
    const AnchorPublishResult result = channel_->publish(record.event);
    for (const auto& endpoint : result.endpoints) {
      if (endpoint.status == AnchorPublishStatus::Accepted ||
          endpoint.status == AnchorPublishStatus::AlreadyPresent) {
        if (configured_relays.count(endpoint.endpoint) == 0) continue;
        record.accepted_endpoints.insert(endpoint.endpoint);
      }
    }
    trust_.save_outbox(record);
    if (record.accepted_endpoints.size() >= config_.publish_quorum) {
      trust_.cache_event(record.event);
    }
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
  const std::set<std::string> configured_relays(
      config_.relay_urls.begin(), config_.relay_urls.end());
  for (const auto& endpoint : result.endpoints) {
    if (endpoint.status == AnchorPublishStatus::Accepted ||
        endpoint.status == AnchorPublishStatus::AlreadyPresent) {
      if (configured_relays.count(endpoint.endpoint) == 0) continue;
      record.accepted_endpoints.insert(endpoint.endpoint);
    }
  }
  trust_.save_outbox(record);
  if (record.accepted_endpoints.size() < config_.publish_quorum) {
    throw std::runtime_error("anchor event did not reach W=2: " +
                             publish_failure_detail(result));
  }
  trust_.cache_event(event);
  return result;
}

SignedNostrEvent AnchorCoordinator::make_proposal(
    const PreparedWriteRecord& prepared) const {
  const AnchorCheckpoint checkpoint = trust_.load_checkpoint();
  HeadProposalEvent proposal;
  proposal.common.vault_id = config_.vault_id;
  proposal.common.operation_id = prepared.operation_id;
  proposal.common.protocol_epoch = config_.protocol_epoch;
  proposal.common.installation_id = config_.installation_id;
  proposal.previous_head = prepared.previous_head;
  proposal.new_head = prepared.new_head;
  proposal.parent_event_id = checkpoint.tip_event_id;
  return sign_encrypted_anchor_event(
      proposal, now_seconds(), channel_tags(config_),
      engine_.identity().signing_secret);
}

SignedNostrEvent AnchorCoordinator::make_observation(
    const PreparedWriteRecord& prepared,
    const AnchorHash& proposal_event_id,
    const std::string& cloud_revision) const {
  HeadObservationEvent observation;
  observation.common.vault_id = config_.vault_id;
  observation.common.operation_id = prepared.operation_id;
  observation.common.protocol_epoch = config_.protocol_epoch;
  observation.common.installation_id = config_.installation_id;
  observation.proposal_event_id = proposal_event_id;
  observation.expected_previous_head = prepared.previous_head;
  observation.observed_cloud_head = prepared.new_head;
  observation.observed_cloud_revision = cloud_revision;
  return sign_encrypted_anchor_event(
      observation, now_seconds(), channel_tags(config_),
      engine_.identity().signing_secret);
}

SignedNostrEvent AnchorCoordinator::recover_observation(
    const SignedNostrEvent& proposal_event,
    const HeadProposalEvent& proposal,
    const std::string& cloud_revision) {
  PreparedWriteRecord record;
  record.operation_id = proposal.common.operation_id;
  record.previous_head = proposal.previous_head;
  record.new_head = proposal.new_head;
  const SignedNostrEvent observation =
      make_observation(record, proposal_event.id, cloud_revision);
  (void)ensure_published(observation);
  return observation;
}

AnchorCoordinatorStatus AnchorCoordinator::evaluate_current(
    bool read_only_operation,
    bool recover) {
  if (!trust_.checkpoint_exists()) {
    if (!recover) {
      throw std::runtime_error(
          "anchor checkpoint is missing; init or import did not complete");
    }
    replay_outbox();
    const auto cached = trust_.load_cached_events();
    const SignedNostrEvent& genesis_event =
        find_event(cached, config_.genesis_event_id);
    if (genesis_event.kind != kGitVaultAnchorEventKind ||
        genesis_event.tags != channel_tags(config_)) {
      throw std::runtime_error(
          "incomplete initialization has an invalid Genesis envelope");
    }
    const AnchorEventPayload decoded =
        state_context().decode_event(genesis_event);
    const auto* genesis = std::get_if<VaultGenesisEvent>(&decoded);
    if (genesis == nullptr || genesis->common.vault_id != config_.vault_id ||
        genesis->common.protocol_epoch != config_.protocol_epoch ||
        genesis->config_hash != config_.config_hash ||
        !engine_.verify_commit_parent(genesis->initial_head, AnchorHash{})) {
      throw std::runtime_error(
          "incomplete initialization Genesis validation failed");
    }
    const VersionedBytes cloud = store_.read_cloud_head_versioned();
    if (engine_.decrypt_head(cloud.bytes) != genesis->initial_head) {
      throw std::runtime_error(
          "cloud HEAD changed before Genesis checkpoint recovery");
    }
    store_.write_local_head(cloud.bytes);
    trust_.save_checkpoint(
        {1, genesis->initial_head, genesis_event.id, cloud.revision});
    trust_.remove_outbox(genesis_event.id);
  }
  if (recover) replay_outbox();

  AnchorCoordinatorStatus status;
  const AnchorCheckpoint checkpoint = trust_.load_checkpoint();
  const VersionedBytes cloud = store_.read_cloud_head_versioned();
  status.cloud_revision = cloud.revision;
  status.cloud_head_bytes = cloud.bytes;
  status.cloud_head = engine_.decrypt_head(cloud.bytes);
  status.local_head = engine_.decrypt_head(store_.read_local_head());

  AnchorChannelQuery query;
  query.author = config_.vault_public_key;
  query.kind = kGitVaultAnchorEventKind;
  query.required_tags = channel_tags(config_);
  status.relay_fetch = channel_->fetch(query);
  const std::vector<SignedNostrEvent> events = merge_events(
      trust_.load_cached_events(), status.relay_fetch.events);

  AnchorStateInput input;
  input.events = events;
  input.local_head = status.local_head;
  input.cloud_head = status.cloud_head;
  input.channel_synchronized =
      synchronized_configured_relays(status.relay_fetch, config_) >=
      config_.read_quorum;
  input.read_only_operation = read_only_operation;
  input.checkpoint_head = checkpoint.accepted_head;
  if (trust_.prepared_exists()) {
    status.prepared = trust_.load_prepared();
    input.prepared_write = transition(*status.prepared);
  }
  status.pending_outbox = trust_.load_outbox();
  status.decision = evaluate_anchor_state(state_context(), input);
  if (status.decision.reason != AnchorStateReason::IncompleteRelaySync) {
    status.observed_head = status.decision.verified_tip;
  }
  const auto relation = [this](const AnchorHash& left,
                               const AnchorHash& right) {
    if (left == right) return std::string("==");
    try {
      if (engine_.is_commit_ancestor(left, right)) return std::string("<");
      if (engine_.is_commit_ancestor(right, left)) return std::string(">");
      return std::string("parallel");
    } catch (const std::exception&) {
      return std::string("unknown");
    }
  };
  status.local_cloud_relation = relation(status.local_head, status.cloud_head);
  status.cloud_observed_relation = status.observed_head.has_value()
      ? relation(status.cloud_head, *status.observed_head)
      : "unavailable";
  status.local_observed_relation = status.observed_head.has_value()
      ? relation(status.local_head, *status.observed_head)
      : "unavailable";

  if (input.channel_synchronized &&
      status.decision.state != AnchorClientState::RecoveryRequired) {
    std::set<AnchorHash> cache_ids{
        status.decision.valid_proposal_event_ids.begin(),
        status.decision.valid_proposal_event_ids.end()};
    cache_ids.insert(status.decision.valid_observation_event_ids.begin(),
                     status.decision.valid_observation_event_ids.end());
    cache_ids.insert(config_.genesis_event_id);
    for (const auto& event : events) {
      if (cache_ids.count(event.id) != 0) trust_.cache_event(event);
    }
  }

  if (!recover) return status;

  if (status.prepared.has_value() &&
      status.decision.reason == AnchorStateReason::IncompleteRelaySync &&
      status.cloud_head == status.prepared->new_head) {
    return resume_prepared(*status.prepared, status, read_only_operation);
  }

  if (status.prepared.has_value() &&
      (status.decision.state == AnchorClientState::WritePrepared ||
       status.decision.state == AnchorClientState::Proposed ||
       status.decision.state == AnchorClientState::ObservationRequired ||
       status.decision.state == AnchorClientState::Announced)) {
    return resume_prepared(*status.prepared, status, read_only_operation);
  }

  if (status.decision.state == AnchorClientState::ObservationRequired &&
      status.decision.proposal_to_observe.has_value()) {
    const SignedNostrEvent& proposal_event =
        find_event(events, *status.decision.proposal_to_observe);
    const AnchorEventPayload decoded = state_context().decode_event(
        proposal_event);
    const auto* proposal = std::get_if<HeadProposalEvent>(&decoded);
    if (proposal == nullptr || proposal->new_head != status.cloud_head) {
      throw std::runtime_error(
          "cloud-matching Proposal failed Observation recovery validation");
    }
    const SignedNostrEvent observation = recover_observation(
        proposal_event, *proposal, status.cloud_revision);
    trust_.cache_event(observation);
    adopt_published_observation(status.cloud_head, observation.id,
                                {status.cloud_head_bytes,
                                 status.cloud_revision});
    trust_.remove_outbox(observation.id);
    AnchorCoordinatorStatus recovered =
        evaluate_current(read_only_operation, false);
    return recovered;
  }

  if (status.decision.state == AnchorClientState::LocalCatchUp ||
      status.decision.state == AnchorClientState::Announced ||
      status.decision.state == AnchorClientState::Consistent) {
    adopt_checkpoint(status);
    status.local_head = status.cloud_head;
    if (status.prepared.has_value()) {
      finalize_prepared(*status.prepared);
      status.prepared.reset();
      status.pending_outbox.clear();
    }
  }
  return status;
}

void AnchorCoordinator::adopt_checkpoint(
    const AnchorCoordinatorStatus& current) {
  if (current.cloud_head != current.decision.verified_tip) {
    throw std::runtime_error(
        "refusing to checkpoint a cloud HEAD that is not the observed tip");
  }
  store_.write_local_head(current.cloud_head_bytes);
  trust_.save_checkpoint({1, current.cloud_head,
                          current.decision.verified_tip_event_id,
                          current.cloud_revision});
}

void AnchorCoordinator::adopt_published_observation(
    const AnchorHash& head,
    const AnchorHash& observation_event_id,
    const VersionedBytes& cloud) {
  if (engine_.decrypt_head(cloud.bytes) != head) {
    throw std::runtime_error(
        "refusing to checkpoint an Observation for a different cloud HEAD");
  }
  store_.write_local_head(cloud.bytes);
  trust_.save_checkpoint({1, head, observation_event_id, cloud.revision});
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
  SignedNostrEvent proposal_event;
  if (!prepared.proposal_event_id.has_value()) {
    proposal_event = make_proposal(prepared);
    trust_.save_outbox({proposal_event, {}});
    prepared.proposal_event_id = proposal_event.id;
    trust_.save_prepared(prepared);
  } else {
    proposal_event = find_known_event(trust_, *prepared.proposal_event_id);
  }
  (void)ensure_published(proposal_event);
  prepared.phase = PreparedWritePhase::ProposalPublished;
  trust_.save_prepared(prepared);

  VersionedBytes cloud = store_.read_cloud_head_versioned();
  AnchorHash cloud_head = engine_.decrypt_head(cloud.bytes);
  if (cloud_head == prepared.previous_head) {
    const ConditionalWriteResult updated = store_.compare_exchange_cloud_head(
        prepared.encrypted_head_bytes, prepared.cloud_revision);
    if (updated.status == ConditionalWriteStatus::Conflict) {
      if (prepared.proposal_event_id.has_value()) {
        trust_.remove_outbox(*prepared.proposal_event_id);
      }
      trust_.clear_prepared();
      throw std::runtime_error(
          "Dropbox HEAD CAS conflict; prepared objects and Proposal were "
          "preserved, reload and retry the command");
    }
    cloud = store_.read_cloud_head_versioned();
    cloud_head = engine_.decrypt_head(cloud.bytes);
  }
  if (cloud_head != prepared.new_head) {
    throw std::runtime_error(
        "cloud HEAD no longer matches the prepared transition");
  }
  prepared.cloud_revision = cloud.revision;
  prepared.phase = PreparedWritePhase::HeadUpdated;
  trust_.save_prepared(prepared);

  SignedNostrEvent observation;
  if (!prepared.observation_event_id.has_value()) {
    observation = make_observation(prepared, *prepared.proposal_event_id,
                                   cloud.revision);
    trust_.save_outbox({observation, {}});
    prepared.observation_event_id = observation.id;
    trust_.save_prepared(prepared);
  } else {
    observation = find_known_event(trust_, *prepared.observation_event_id);
  }
  (void)ensure_published(observation);
  prepared.phase = PreparedWritePhase::ObservationPublished;
  trust_.save_prepared(prepared);
  adopt_published_observation(prepared.new_head, observation.id, cloud);
  finalize_prepared(prepared);
  AnchorCoordinatorStatus completed =
      evaluate_current(read_only_operation, false);
  return completed;
}

AnchorCoordinatorStatus AnchorCoordinator::preflight(
    bool read_only_operation) {
  return evaluate_current(read_only_operation, true);
}

PreparedVaultWrite AnchorCoordinator::execute_write(
    const std::function<PreparedVaultWrite(const AnchorHash&)>& prepare) {
  AnchorCoordinatorStatus status = preflight(false);
  if (status.decision.state != AnchorClientState::Consistent) {
    throw std::runtime_error(
        std::string("write requires CONSISTENT state; current state is ") +
        anchor_client_state_name(status.decision.state) + " (" +
        anchor_state_reason_name(status.decision.reason) + "): " +
        status.decision.detail);
  }
  const PreparedVaultWrite write = prepare(status.cloud_head);
  PreparedWriteRecord journal;
  journal.operation_id = write.operation_id;
  journal.previous_head = write.previous_head;
  journal.new_head = write.new_head;
  journal.encrypted_head_bytes = write.encrypted_head_bytes;
  journal.phase = PreparedWritePhase::ObjectsPrepared;
  journal.cloud_revision = status.cloud_revision;
  trust_.save_prepared(journal);
  const AnchorCoordinatorStatus completed = preflight(false);
  const AnchorCheckpoint checkpoint = trust_.load_checkpoint();
  if (checkpoint.accepted_head != write.new_head ||
      completed.cloud_head != write.new_head || trust_.prepared_exists()) {
    throw std::runtime_error("write did not reach its observed checkpoint");
  }
  if (completed.decision.state == AnchorClientState::Forked ||
      completed.decision.state == AnchorClientState::RollbackDetected ||
      (completed.decision.state == AnchorClientState::RecoveryRequired &&
       completed.decision.reason != AnchorStateReason::IncompleteRelaySync)) {
    throw std::runtime_error(
        std::string("write reached its checkpoint, but post-write validation ") +
        "stopped in " + anchor_client_state_name(completed.decision.state) +
        " (" + anchor_state_reason_name(completed.decision.reason) + ")");
  }
  return write;
}

const AnchorChannelConfig& AnchorCoordinator::config() const {
  return config_;
}
