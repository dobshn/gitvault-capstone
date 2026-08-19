#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "anchor_channel.h"
#include "anchor_state_machine.h"
#include "anchor_trust_store.h"
#include "object_store.h"
#include "vault_engine.h"

struct AnchorCoordinatorStatus {
  AnchorStateResult decision;
  AnchorHash local_head{};
  AnchorHash cloud_head{};
  VaultHeadState local_head_state;
  VaultHeadState cloud_head_state;
  std::optional<AnchorHash> observed_head;
  ByteVec cloud_head_bytes;
  std::string cloud_revision;
  std::string local_cloud_relation;
  std::string cloud_observed_relation;
  std::string local_observed_relation;
  AnchorFetchResult relay_fetch;
  std::optional<PreparedWriteRecord> prepared;
  std::vector<AnchorOutboxRecord> pending_outbox;
};

class AnchorCoordinator {
public:
  AnchorCoordinator(ObjectStore& store,
                    VaultEngine& engine,
                    std::unique_ptr<IAnchorChannel> channel);

  static AnchorChannelConfig initialize(
      ObjectStore& store,
      VaultEngine& engine,
      IAnchorChannel& channel,
      const std::vector<std::string>& relay_urls);

  // Inspect remote and local anchor state without advancing trusted local state.
  AnchorCoordinatorStatus preflight(bool read_only_operation);
  // Perform safe pending-write recovery and verified local catch-up.
  AnchorCoordinatorStatus synchronize();
  bool execute_destroy(const std::function<bool()>& destroy_remote);
  PreparedVaultWrite execute_write(
      const std::function<PreparedVaultWrite(const AnchorHash&)>& prepare);

  const AnchorChannelConfig& config() const;

private:
  AnchorStateContext state_context() const;
  AnchorCoordinatorStatus evaluate_current(bool read_only_operation,
                                           bool recover);
  void replay_outbox();
  AnchorPublishResult ensure_published(const SignedNostrEvent& event);
  SignedNostrEvent make_checkpoint(
      const VaultHeadState& head,
      const ByteVec& head_envelope,
      const std::string& cloud_revision);
  void publish_and_adopt_checkpoint(const VaultHeadState& head,
                                    const VersionedBytes& cloud);
  AnchorCoordinatorStatus resume_prepared(
      PreparedWriteRecord prepared,
      const AnchorCoordinatorStatus& current,
      bool read_only_operation);
  void adopt_checkpoint(const AnchorCoordinatorStatus& current);
  void adopt_published_observation(
      const AnchorHash& head,
      const AnchorHash& checkpoint_event_id,
      const VersionedBytes& cloud);
  void finalize_prepared(const PreparedWriteRecord& prepared);

  ObjectStore& store_;
  VaultEngine& engine_;
  std::unique_ptr<IAnchorChannel> channel_;
  AnchorTrustStore trust_;
  AnchorChannelConfig config_;
};
