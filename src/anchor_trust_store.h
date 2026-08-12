#pragma once

#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "anchor_event.h"
#include "util.h"

struct AnchorChannelConfig {
  uint8_t format_version = 2;
  uint8_t protocol_version = kAnchorProtocolVersion;
  uint64_t protocol_epoch = 0;
  AnchorHash vault_id{};
  AnchorHash channel_id{};
  SchnorrPublicKey vault_public_key{};
  AnchorHash genesis_event_id{};
  AnchorHash config_hash{};
  std::string installation_id;
  std::vector<std::string> relay_urls;
  uint8_t publish_quorum = 2;
  uint8_t read_quorum = 2;
};

struct AnchorCheckpoint {
  uint8_t format_version = 2;
  uint64_t protocol_epoch = 0;
  AnchorHash accepted_head{};
  VectorClock accepted_clock;
  AnchorHash head_envelope_hash{};
  AnchorHash tip_event_id{};
  std::string cloud_revision;
  uint64_t last_checkpoint_created_at = 0;
};

enum class PreparedWritePhase {
  ObjectsPrepared,
  ProposalPublished,
  HeadUpdated,
  ObservationPublished,
};

struct PreparedWriteRecord {
  uint8_t format_version = 2;
  uint64_t protocol_epoch = 0;
  AnchorOperationId operation_id{};
  AnchorHash previous_head{};
  AnchorHash new_head{};
  VectorClock previous_clock;
  VectorClock new_clock;
  ByteVec encrypted_head_bytes;
  PreparedWritePhase phase = PreparedWritePhase::ObjectsPrepared;
  std::optional<AnchorHash> proposal_event_id;
  std::optional<AnchorHash> observation_event_id;
  std::string cloud_revision;
};

struct AnchorOutboxRecord {
  SignedNostrEvent event;
  std::set<std::string> accepted_endpoints;
};

class AnchorTrustStore {
public:
  AnchorTrustStore(std::filesystem::path trust_directory, ByteVec mac_key);

  bool channel_exists() const;
  void save_channel(const AnchorChannelConfig& config) const;
  AnchorChannelConfig load_channel() const;

  bool checkpoint_exists() const;
  void save_checkpoint(const AnchorCheckpoint& checkpoint) const;
  AnchorCheckpoint load_checkpoint() const;

  bool prepared_exists() const;
  void save_prepared(const PreparedWriteRecord& prepared) const;
  PreparedWriteRecord load_prepared() const;
  void clear_prepared() const;

  void cache_event(const SignedNostrEvent& event) const;
  std::vector<SignedNostrEvent> load_cached_events(size_t limit = 4096) const;

  void save_witness(const ReplicaId& replica_id,
                    const SignedNostrEvent& event) const;
  std::vector<SignedNostrEvent> load_witnesses(
      size_t limit = kMaximumVectorClockEntries) const;

  void save_outbox(const AnchorOutboxRecord& record) const;
  std::vector<AnchorOutboxRecord> load_outbox(size_t limit = 4096) const;
  void remove_outbox(const AnchorHash& event_id) const;

  const std::filesystem::path& trust_directory() const;

private:
  std::filesystem::path authenticated_path(const char* name) const;
  std::filesystem::path event_directory() const;
  std::filesystem::path outbox_directory() const;
  std::filesystem::path witness_directory() const;
  void ensure_directories() const;

  std::filesystem::path trust_directory_;
  ByteVec mac_key_;
};

const char* prepared_write_phase_name(PreparedWritePhase phase);

std::string serialize_anchor_channel_config(
    const AnchorChannelConfig& config);
AnchorChannelConfig deserialize_anchor_channel_config(
    const std::string& canonical_json);
std::string serialize_anchor_checkpoint(
    const AnchorCheckpoint& checkpoint);
AnchorCheckpoint deserialize_anchor_checkpoint(
    const std::string& canonical_json);
