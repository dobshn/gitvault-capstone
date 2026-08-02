#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "anchor_event.h"

enum class AnchorClientState {
  Consistent,
  LocalCatchUp,
  WritePrepared,
  Proposed,
  ObservationRequired,
  Announced,
  DegradedReadOnly,
  RollbackDetected,
  Forked,
  RecoveryRequired,
};

enum class AnchorStateReason {
  None,
  LocalBehind,
  CloudBehindObservedTip,
  CloudMatchesPendingProposal,
  UnexplainedCloudHead,
  DivergentObservedBranches,
  IncompleteRelaySync,
  InvalidCommitParent,
  MissingReference,
  PreparedWriteAhead,
  InvalidEventGraph,
};

enum class AnchorStateAction {
  None,
  AdoptVerifiedTip,
  PublishObservation,
  RetryPublish,
  AbortWrite,
  Stop,
};

struct PreparedHeadTransition {
  AnchorOperationId operation_id{};
  AnchorHash previous_head{};
  AnchorHash new_head{};
};

using CommitParentVerifier = std::function<bool(
    const AnchorHash& commit_hash,
    const AnchorHash& expected_parent_hash)>;
using CommitAncestorVerifier = std::function<bool(
    const AnchorHash& ancestor_hash,
    const AnchorHash& descendant_hash)>;
using AnchorEventDecoder =
    std::function<AnchorEventPayload(const SignedNostrEvent& event)>;

struct AnchorStateContext {
  SchnorrPublicKey trusted_public_key{};
  AnchorHash expected_vault_id{};
  AnchorHash expected_config_hash{};
  std::optional<std::string> expected_channel_tag;
  uint64_t expected_protocol_epoch = 0;
  AnchorHash genesis_event_id{};
  CommitParentVerifier verify_commit_parent;
  CommitAncestorVerifier is_commit_ancestor;
  AnchorEventDecoder decode_event;
};

struct AnchorStateInput {
  std::vector<SignedNostrEvent> events;
  AnchorHash local_head{};
  AnchorHash cloud_head{};
  std::optional<PreparedHeadTransition> prepared_write;
  bool channel_synchronized = true;
  bool read_only_operation = false;
  std::optional<AnchorHash> checkpoint_head;
};

struct AnchorStateResult {
  AnchorClientState state = AnchorClientState::RecoveryRequired;
  AnchorStateReason reason = AnchorStateReason::None;
  AnchorStateAction action = AnchorStateAction::None;
  AnchorHash verified_tip{};
  AnchorHash verified_tip_event_id{};
  std::optional<AnchorHash> local_head_to_adopt;
  std::optional<AnchorHash> proposal_to_observe;
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
const char* anchor_state_reason_name(AnchorStateReason reason);
const char* anchor_state_action_name(AnchorStateAction action);
