#include "checkpoint_state_machine.h"

#include <algorithm>
#include <map>
#include <stdexcept>

#include "util.h"

namespace {
struct Witness {
  SignedNostrEvent event;
  HeadCheckpointEvent checkpoint;
  ReplicaId replica_id{};
};

bool state_matches(const HeadCheckpointEvent& checkpoint,
                   const VaultHeadState& head,
                   const AnchorHash& envelope_hash) {
  return checkpoint.common.protocol_epoch == head.protocol_epoch &&
         checkpoint.head == head.head && checkpoint.clock == head.clock &&
         checkpoint.common.operation_id == head.operation_id &&
         checkpoint.head_envelope_hash == envelope_hash;
}

bool checkpoints_identical(const HeadCheckpointEvent& left,
                           const HeadCheckpointEvent& right) {
  return left.common.protocol_epoch == right.common.protocol_epoch &&
         left.common.operation_id == right.common.operation_id &&
         left.head == right.head && left.clock == right.clock &&
         left.head_envelope_hash == right.head_envelope_hash;
}

ReplicaId replica_from_installation(const std::string& installation_id) {
  if (installation_id.size() != 32) {
    throw std::runtime_error("checkpoint installation_id is not 128-bit hex");
  }
  const ByteVec decoded = from_hex(installation_id);
  if (decoded.size() != 16) {
    throw std::runtime_error("checkpoint installation_id is invalid");
  }
  ReplicaId result{};
  std::copy(decoded.begin(), decoded.end(), result.begin());
  return result;
}

std::string checkpoint_address(const AnchorStateContext& context,
                               const std::string& installation_id) {
  return "gitvault:" + to_hex(context.expected_vault_id) + ":" +
         installation_id;
}

AnchorStateResult stopped(AnchorClientState state,
                          AnchorStateReason reason,
                          const std::string& detail) {
  AnchorStateResult result;
  result.state = state;
  result.reason = reason;
  result.action = AnchorStateAction::Stop;
  result.detail = detail;
  return result;
}
}  // namespace

AnchorStateResult evaluate_checkpoint_state(
    const AnchorStateContext& context,
    const CheckpointStateInput& input) {
  if (input.local_checkpoint.protocol_epoch !=
          context.expected_protocol_epoch ||
      input.local_head.protocol_epoch != context.expected_protocol_epoch ||
      input.cloud_head.protocol_epoch != context.expected_protocol_epoch) {
    return stopped(AnchorClientState::RecoveryRequired,
                   AnchorStateReason::InvalidEventGraph,
                   "HEAD/checkpoint protocol epoch mismatch");
  }
  if (input.local_checkpoint.accepted_head != input.local_head.head ||
      input.local_checkpoint.accepted_clock != input.local_head.clock) {
    return stopped(AnchorClientState::RecoveryRequired,
                   AnchorStateReason::InvalidEventGraph,
                   "local HEAD does not match the authenticated checkpoint");
  }

  if (!input.channel_synchronized) {
    if (input.read_only_operation &&
        input.local_head.head == input.cloud_head.head &&
        input.local_head.clock == input.cloud_head.clock) {
      AnchorStateResult result;
      result.state = AnchorClientState::DegradedReadOnly;
      result.reason = AnchorStateReason::IncompleteRelaySync;
      result.verified_tip = input.local_head.head;
      result.verified_clock = input.local_head.clock;
      result.detail =
          "relay synchronization is incomplete; serving the local trusted "
          "checkpoint without freshness";
      return result;
    }
    return stopped(AnchorClientState::RecoveryRequired,
                   AnchorStateReason::IncompleteRelaySync,
                   "checkpoint witness synchronization is incomplete");
  }

  std::vector<Witness> witnesses;
  for (const auto& event : input.witness_events) {
    if (event.kind != kGitVaultCheckpointEventKind ||
        !verify_nostr_event(event, context.trusted_public_key)) {
      continue;
    }
    try {
      const AnchorEventPayload decoded = context.decode_event
          ? context.decode_event(event)
          : deserialize_anchor_event_payload(event.content);
      const auto* checkpoint = std::get_if<HeadCheckpointEvent>(&decoded);
      if (checkpoint == nullptr ||
          checkpoint->common.protocol_version != kAnchorProtocolVersion ||
          checkpoint->common.protocol_epoch !=
              context.expected_protocol_epoch ||
          checkpoint->common.vault_id != context.expected_vault_id) {
        continue;
      }
      const ReplicaId replica =
          replica_from_installation(checkpoint->common.installation_id);
      if (!context.expected_channel_tag.has_value()) {
        continue;
      }
      const std::vector<NostrTag> expected_tags = {
          {"t", *context.expected_channel_tag},
          {"d", checkpoint_address(
                    context, checkpoint->common.installation_id)}};
      if (event.tags != expected_tags) {
        continue;
      }
      validate_vector_clock(checkpoint->clock);
      witnesses.push_back({event, *checkpoint, replica});
    } catch (const std::exception&) {
      continue;
    }
  }

  if (witnesses.empty()) {
    return stopped(AnchorClientState::RecoveryRequired,
                   AnchorStateReason::MissingReference,
                   "no valid signed checkpoint witness was found");
  }

  size_t maximum = 0;
  for (size_t left = 0; left < witnesses.size(); ++left) {
    for (size_t right = left + 1; right < witnesses.size(); ++right) {
      const VectorClockRelation relation = compare_vector_clocks(
          witnesses[left].checkpoint.clock,
          witnesses[right].checkpoint.clock);
      if (relation == VectorClockRelation::Concurrent ||
          (relation == VectorClockRelation::Equal &&
           !checkpoints_identical(witnesses[left].checkpoint,
                                  witnesses[right].checkpoint))) {
        AnchorStateResult result = stopped(
            AnchorClientState::Forked,
            AnchorStateReason::DivergentObservedBranches,
            relation == VectorClockRelation::Concurrent
                ? "incompatible signed checkpoint vector clocks were found"
                : "equal vector clocks authenticate different HEAD states");
        result.fork_heads = {witnesses[left].checkpoint.head,
                             witnesses[right].checkpoint.head};
        return result;
      }
    }
    if (compare_vector_clocks(witnesses[maximum].checkpoint.clock,
                              witnesses[left].checkpoint.clock) ==
        VectorClockRelation::Before) {
      maximum = left;
    }
  }

  const Witness& latest = witnesses[maximum];
  AnchorStateResult result;
  result.verified_tip = latest.checkpoint.head;
  result.verified_clock = latest.checkpoint.clock;
  result.verified_tip_event_id = latest.event.id;
  result.verified_head_envelope_hash = latest.checkpoint.head_envelope_hash;
  for (const auto& witness : witnesses) {
    result.valid_observation_event_ids.push_back(witness.event.id);
  }

  const VectorClockRelation witness_cloud = compare_vector_clocks(
      latest.checkpoint.clock, input.cloud_head.clock);
  if (witness_cloud == VectorClockRelation::Concurrent) {
    result.state = AnchorClientState::Forked;
    result.reason = AnchorStateReason::DivergentObservedBranches;
    result.action = AnchorStateAction::Stop;
    result.detail = "Dropbox HEAD is incompatible with a signed checkpoint";
    result.fork_heads = {latest.checkpoint.head, input.cloud_head.head};
    return result;
  }
  if (witness_cloud == VectorClockRelation::After) {
    result.state = AnchorClientState::RollbackDetected;
    result.reason = AnchorStateReason::CloudBehindObservedTip;
    result.action = AnchorStateAction::Stop;
    result.detail = "Dropbox HEAD is behind the latest signed checkpoint";
    return result;
  }
  if (witness_cloud == VectorClockRelation::Equal &&
      !state_matches(latest.checkpoint, input.cloud_head,
                     input.cloud_head_envelope_hash)) {
    result.state = AnchorClientState::Forked;
    result.reason = AnchorStateReason::DivergentObservedBranches;
    result.action = AnchorStateAction::Stop;
    result.detail = "equal vector clocks authenticate different cloud states";
    result.fork_heads = {latest.checkpoint.head, input.cloud_head.head};
    return result;
  }
  if (witness_cloud == VectorClockRelation::Before) {
    result.state = AnchorClientState::ObservationRequired;
    result.reason = AnchorStateReason::CloudMatchesPendingProposal;
    result.action = AnchorStateAction::PublishObservation;
    result.detail = "Dropbox HEAD is ahead and needs a signed checkpoint";
    return result;
  }

  const VectorClockRelation local_cloud = compare_vector_clocks(
      input.local_checkpoint.accepted_clock, input.cloud_head.clock);
  if (local_cloud == VectorClockRelation::Concurrent) {
    result.state = AnchorClientState::Forked;
    result.reason = AnchorStateReason::DivergentObservedBranches;
    result.action = AnchorStateAction::Stop;
    result.detail = "local trusted checkpoint and Dropbox HEAD are incompatible";
    return result;
  }
  if (local_cloud == VectorClockRelation::After) {
    result.state = AnchorClientState::RollbackDetected;
    result.reason = AnchorStateReason::CloudBehindObservedTip;
    result.action = AnchorStateAction::Stop;
    result.detail = "Dropbox HEAD is behind the local trusted checkpoint";
    return result;
  }
  if (local_cloud == VectorClockRelation::Equal &&
      input.local_checkpoint.accepted_head != input.cloud_head.head) {
    result.state = AnchorClientState::Forked;
    result.reason = AnchorStateReason::DivergentObservedBranches;
    result.action = AnchorStateAction::Stop;
    result.detail = "equal local/cloud vector clocks contain different HEADs";
    return result;
  }
  if (local_cloud == VectorClockRelation::Before) {
    result.state = AnchorClientState::LocalCatchUp;
    result.reason = AnchorStateReason::LocalBehind;
    result.action = AnchorStateAction::AdoptVerifiedTip;
    result.local_head_to_adopt = input.cloud_head.head;
    result.detail = "signed comparable cloud checkpoint advances local state";
    return result;
  }

  if (input.prepared_write_exists) {
    result.state = AnchorClientState::WritePrepared;
    result.reason = AnchorStateReason::PreparedWriteAhead;
    result.action = AnchorStateAction::RetryPublish;
    result.detail = "a durable write journal is pending";
    return result;
  }
  result.state = AnchorClientState::Consistent;
  result.detail = "local, Dropbox, and signed vector checkpoints agree";
  return result;
}
