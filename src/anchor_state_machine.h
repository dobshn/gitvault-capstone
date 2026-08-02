#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "anchor_event.h"

enum class AnchorClientState {
  Consistent,
  WritePrepared,
  Proposed,
  HeadUpdated,
  Announced,
  Forked,
  RecoveryRequired,
};

struct PreparedHeadTransition {
  AnchorOperationId operation_id{};
  AnchorHash previous_head{};
  AnchorHash new_head{};
};

using CommitParentVerifier = std::function<bool(
    const AnchorHash& commit_hash,
    const AnchorHash& expected_parent_hash)>;

struct AnchorStateContext {
  SchnorrPublicKey trusted_public_key{};
  AnchorHash expected_vault_id{};
  AnchorHash expected_config_hash{};
  uint64_t expected_protocol_epoch = 0;
  AnchorHash genesis_event_id{};
  CommitParentVerifier verify_commit_parent;
};

struct AnchorStateInput {
  std::vector<SignedNostrEvent> events;
  AnchorHash local_head{};
  AnchorHash cloud_head{};
  std::optional<PreparedHeadTransition> prepared_write;
  bool channel_synchronized = true;
};

struct AnchorStateResult {
  AnchorClientState state = AnchorClientState::RecoveryRequired;
  AnchorHash verified_tip{};
  std::optional<AnchorHash> local_head_to_adopt;
  std::vector<AnchorHash> valid_proposal_event_ids;
  std::vector<AnchorHash> valid_observation_event_ids;
  std::vector<AnchorHash> pending_proposal_event_ids;
  std::vector<AnchorHash> rejected_event_ids;
  std::vector<AnchorHash> unresolved_event_ids;
  std::vector<AnchorHash> fork_heads;
  std::string detail;
};

AnchorStateResult evaluate_anchor_state(
    const AnchorStateContext& context,
    const AnchorStateInput& input);

const char* anchor_client_state_name(AnchorClientState state);
