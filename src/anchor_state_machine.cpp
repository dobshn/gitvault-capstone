#include "anchor_state_machine.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace {
struct CandidateEvent {
  AnchorEventPayload payload;
};

struct ValidatedGraph {
  bool recovery_required = false;
  bool forked = false;
  std::string detail;
  AnchorHash initial_head{};
  AnchorHash tip{};
  AnchorHash tip_event_id{};
  std::map<AnchorHash, HeadProposalEvent> proposals;
  std::map<AnchorHash, HeadObservationEvent> observations;
  std::map<AnchorHash, AnchorHash> transition_heads;
  std::map<AnchorHash, std::set<AnchorHash>> observed_children;
  std::map<AnchorHash, AnchorHash> observed_parent;
  std::set<AnchorHash> observed_proposals;
  std::map<AnchorHash, std::set<AnchorHash>> observation_ids_by_head;
  std::set<AnchorHash> rejected;
  std::set<AnchorHash> unresolved;
  std::set<AnchorHash> fork_heads;
};

void require_recovery(ValidatedGraph& graph, const std::string& detail) {
  graph.recovery_required = true;
  if (graph.detail.empty()) {
    graph.detail = detail;
  }
}

bool common_matches_context(const AnchorEventCommon& common,
                            const AnchorStateContext& context) {
  return common.protocol_version == kAnchorProtocolVersion &&
         common.vault_id == context.expected_vault_id &&
         common.protocol_epoch == context.expected_protocol_epoch;
}

bool verify_commit_parent(const AnchorStateContext& context,
                          const AnchorHash& commit,
                          const AnchorHash& parent) {
  if (!context.verify_commit_parent) {
    throw std::runtime_error("commit parent verifier is not configured");
  }
  return context.verify_commit_parent(commit, parent);
}

bool is_commit_ancestor(const AnchorStateContext& context,
                        const AnchorHash& ancestor,
                        const AnchorHash& descendant) {
  if (ancestor == descendant) {
    return true;
  }
  if (!context.is_commit_ancestor) {
    throw std::runtime_error("commit ancestry verifier is not configured");
  }
  return context.is_commit_ancestor(ancestor, descendant);
}

AnchorStateReason validation_reason(const ValidatedGraph& graph) {
  if (graph.detail.find("missing") != std::string::npos ||
      graph.detail.find("references") != std::string::npos) {
    return AnchorStateReason::MissingReference;
  }
  if (graph.detail.find("Commit") != std::string::npos ||
      graph.detail.find("parent") != std::string::npos) {
    return AnchorStateReason::InvalidCommitParent;
  }
  return AnchorStateReason::InvalidEventGraph;
}

template <typename Container>
std::vector<AnchorHash> to_vector(const Container& values) {
  return std::vector<AnchorHash>(values.begin(), values.end());
}

ValidatedGraph validate_graph(const AnchorStateContext& context,
                              const std::vector<SignedNostrEvent>& events) {
  ValidatedGraph graph;
  std::map<AnchorHash, CandidateEvent> candidates;

  for (const auto& event : events) {
    if (event.kind != kGitVaultAnchorEventKind ||
        !verify_nostr_event(event, context.trusted_public_key)) {
      graph.rejected.insert(event.id);
      continue;
    }

    if (context.expected_channel_tag.has_value() &&
        event.tags != std::vector<NostrTag>{{"t", *context.expected_channel_tag}}) {
      graph.rejected.insert(event.id);
      continue;
    }

    try {
      AnchorEventPayload payload = context.decode_event
                                       ? context.decode_event(event)
                                       : deserialize_anchor_event_payload(
                                             event.content);
      if (!common_matches_context(anchor_event_common(payload), context)) {
        graph.rejected.insert(event.id);
        continue;
      }
      candidates.emplace(event.id, CandidateEvent{std::move(payload)});
    } catch (const std::exception& error) {
      graph.unresolved.insert(event.id);
      require_recovery(graph,
                       std::string("trusted event has invalid payload: ") +
                           error.what());
    }
  }

  const auto genesis_iterator = candidates.find(context.genesis_event_id);
  if (genesis_iterator == candidates.end()) {
    require_recovery(graph, "trusted Genesis event is missing");
    return graph;
  }
  const auto* genesis =
      std::get_if<VaultGenesisEvent>(&genesis_iterator->second.payload);
  if (genesis == nullptr) {
    graph.unresolved.insert(context.genesis_event_id);
    require_recovery(graph, "pinned Genesis ID is not a Genesis event");
    return graph;
  }
  if (genesis->config_hash != context.expected_config_hash) {
    graph.unresolved.insert(context.genesis_event_id);
    require_recovery(graph, "Genesis config hash does not match local config");
    return graph;
  }
  try {
    if (!verify_commit_parent(context, genesis->initial_head, AnchorHash{})) {
      graph.unresolved.insert(context.genesis_event_id);
      require_recovery(
          graph,
          "Genesis Commit is missing or does not have the zero parent");
      return graph;
    }
  } catch (const std::exception& error) {
    graph.unresolved.insert(context.genesis_event_id);
    require_recovery(
        graph,
        std::string("Genesis Commit verification failed: ") + error.what());
    return graph;
  }

  graph.initial_head = genesis->initial_head;
  graph.tip = genesis->initial_head;
  graph.tip_event_id = context.genesis_event_id;
  graph.transition_heads.emplace(context.genesis_event_id,
                                 genesis->initial_head);

  std::set<AnchorHash> processed{context.genesis_event_id};
  for (const auto& [event_id, candidate] : candidates) {
    if (event_id != context.genesis_event_id &&
        std::holds_alternative<VaultGenesisEvent>(candidate.payload)) {
      processed.insert(event_id);
      graph.rejected.insert(event_id);
    }
  }

  bool made_progress = true;
  while (made_progress) {
    made_progress = false;
    for (const auto& [event_id, candidate] : candidates) {
      if (processed.count(event_id) != 0) {
        continue;
      }

      if (const auto* proposal =
              std::get_if<HeadProposalEvent>(&candidate.payload)) {
        const auto parent =
            graph.transition_heads.find(proposal->parent_event_id);
        if (parent == graph.transition_heads.end()) {
          continue;
        }

        processed.insert(event_id);
        made_progress = true;
        if (proposal->previous_head != parent->second) {
          graph.unresolved.insert(event_id);
          require_recovery(
              graph,
              "Proposal previous HEAD does not match its parent event");
          continue;
        }
        if (proposal->previous_head == proposal->new_head) {
          graph.unresolved.insert(event_id);
          require_recovery(graph, "Proposal must advance to a new HEAD");
          continue;
        }
        try {
          if (!verify_commit_parent(context, proposal->new_head,
                                    proposal->previous_head)) {
            graph.unresolved.insert(event_id);
            require_recovery(
                graph,
                "Proposal Commit is missing or has the wrong parent");
            continue;
          }
        } catch (const std::exception& error) {
          graph.unresolved.insert(event_id);
          require_recovery(
              graph,
              std::string("Proposal Commit verification failed: ") +
                  error.what());
          continue;
        }
        graph.proposals.emplace(event_id, *proposal);
        continue;
      }

      if (const auto* observation =
              std::get_if<HeadObservationEvent>(&candidate.payload)) {
        const auto proposal =
            graph.proposals.find(observation->proposal_event_id);
        if (proposal == graph.proposals.end()) {
          continue;
        }

        processed.insert(event_id);
        made_progress = true;
        const HeadProposalEvent& referenced = proposal->second;
        if (observation->common.operation_id !=
                referenced.common.operation_id ||
            observation->expected_previous_head !=
                referenced.previous_head ||
            observation->observed_cloud_head != referenced.new_head) {
          graph.unresolved.insert(event_id);
          require_recovery(
              graph,
              "Observation does not match its referenced Proposal");
          continue;
        }
        graph.observations.emplace(event_id, *observation);
        graph.observation_ids_by_head[observation->observed_cloud_head].insert(
            event_id);
        graph.transition_heads.emplace(event_id,
                                       observation->observed_cloud_head);
        graph.observed_proposals.insert(observation->proposal_event_id);
      }
    }
  }

  for (const auto& [event_id, candidate] : candidates) {
    if (processed.count(event_id) == 0) {
      graph.unresolved.insert(event_id);
      require_recovery(
          graph,
          "signed event references a missing or invalid parent event");
    }
  }

  for (const auto& [observation_id, observation] : graph.observations) {
    (void)observation_id;
    const HeadProposalEvent& proposal =
        graph.proposals.at(observation.proposal_event_id);
    graph.observed_children[proposal.previous_head].insert(proposal.new_head);
    const auto [parent, inserted] =
        graph.observed_parent.emplace(proposal.new_head,
                                      proposal.previous_head);
    if (!inserted && parent->second != proposal.previous_head) {
      graph.forked = true;
      graph.fork_heads.insert(proposal.new_head);
    }
  }

  for (const auto& [parent, children] : graph.observed_children) {
    (void)parent;
    if (children.size() > 1) {
      graph.forked = true;
      graph.fork_heads.insert(children.begin(), children.end());
    }
  }

  if (graph.forked) {
    graph.detail = "multiple observed HEAD branches were found";
    return graph;
  }

  AnchorHash current = graph.initial_head;
  std::set<AnchorHash> visited;
  bool reached_terminal = false;
  while (visited.insert(current).second) {
    const auto children = graph.observed_children.find(current);
    if (children == graph.observed_children.end() || children->second.empty()) {
      graph.tip = current;
      const auto tip_observations = graph.observation_ids_by_head.find(current);
      graph.tip_event_id = tip_observations == graph.observation_ids_by_head.end()
                               ? context.genesis_event_id
                               : *tip_observations->second.begin();
      reached_terminal = true;
      break;
    }
    if (children->second.size() != 1) {
      graph.forked = true;
      graph.detail = "multiple observed HEAD branches were found";
      graph.fork_heads.insert(children->second.begin(),
                              children->second.end());
      return graph;
    }
    current = *children->second.begin();
  }
  if (!reached_terminal) {
    require_recovery(graph, "observed HEAD graph contains a cycle");
  }
  return graph;
}

bool is_observed_ancestor(const ValidatedGraph& graph,
                          const AnchorHash& ancestor,
                          const AnchorHash& descendant) {
  AnchorHash current = descendant;
  std::set<AnchorHash> visited;
  while (visited.insert(current).second) {
    if (current == ancestor) {
      return true;
    }
    const auto parent = graph.observed_parent.find(current);
    if (parent == graph.observed_parent.end()) {
      return false;
    }
    current = parent->second;
  }
  return false;
}

bool proposal_matches_prepared(const HeadProposalEvent& proposal,
                               const PreparedHeadTransition& prepared) {
  return proposal.common.operation_id == prepared.operation_id &&
         proposal.previous_head == prepared.previous_head &&
         proposal.new_head == prepared.new_head;
}

void copy_graph_diagnostics(const ValidatedGraph& graph,
                            AnchorStateResult& result) {
  for (const auto& [event_id, proposal] : graph.proposals) {
    (void)proposal;
    result.valid_proposal_event_ids.push_back(event_id);
    if (graph.observed_proposals.count(event_id) == 0) {
      result.pending_proposal_event_ids.push_back(event_id);
    }
  }
  for (const auto& [event_id, observation] : graph.observations) {
    (void)observation;
    result.valid_observation_event_ids.push_back(event_id);
  }
  result.rejected_event_ids = to_vector(graph.rejected);
  result.unresolved_event_ids = to_vector(graph.unresolved);
  result.fork_heads = to_vector(graph.fork_heads);
}
}  // namespace

AnchorStateResult evaluate_anchor_state(
    const AnchorStateContext& context,
    const AnchorStateInput& input) {
  AnchorStateResult result;
  if (!input.channel_synchronized) {
    result.reason = AnchorStateReason::IncompleteRelaySync;
    if (input.read_only_operation && input.checkpoint_head.has_value() &&
        input.local_head == input.cloud_head &&
        input.local_head == *input.checkpoint_head) {
      result.state = AnchorClientState::DegradedReadOnly;
      result.action = AnchorStateAction::None;
      result.verified_tip = *input.checkpoint_head;
      result.detail =
          "relay synchronization is incomplete; serving the last verified "
          "checkpoint without freshness";
      return result;
    }
    result.state = AnchorClientState::RecoveryRequired;
    result.action = AnchorStateAction::Stop;
    result.detail = "anchor channel synchronization is incomplete";
    return result;
  }

  ValidatedGraph graph = validate_graph(context, input.events);
  result.verified_tip = graph.tip;
  result.verified_tip_event_id = graph.tip_event_id;
  copy_graph_diagnostics(graph, result);
  if (graph.forked) {
    result.state = AnchorClientState::Forked;
    result.reason = AnchorStateReason::DivergentObservedBranches;
    result.action = AnchorStateAction::Stop;
    result.detail = graph.detail;
    return result;
  }
  if (graph.recovery_required) {
    result.state = AnchorClientState::RecoveryRequired;
    result.reason = validation_reason(graph);
    result.action = AnchorStateAction::Stop;
    result.detail = graph.detail;
    return result;
  }

  std::vector<std::pair<AnchorHash, HeadProposalEvent>> pending_from_tip;
  for (const auto& [event_id, proposal] : graph.proposals) {
    if (graph.observed_proposals.count(event_id) == 0 &&
        proposal.previous_head == graph.tip) {
      pending_from_tip.emplace_back(event_id, proposal);
    }
  }

  bool active_prepared_write = false;
  bool completed_prepared_write = false;
  if (input.prepared_write.has_value()) {
    const PreparedHeadTransition& prepared = *input.prepared_write;
    if (prepared.previous_head == graph.tip &&
        prepared.new_head != prepared.previous_head) {
      try {
        if (!verify_commit_parent(context, prepared.new_head,
                                  prepared.previous_head)) {
          result.state = AnchorClientState::RecoveryRequired;
          result.reason = AnchorStateReason::InvalidCommitParent;
          result.action = AnchorStateAction::AbortWrite;
          result.detail = "prepared Commit is missing or has the wrong parent";
          return result;
        }
      } catch (const std::exception& error) {
        result.state = AnchorClientState::RecoveryRequired;
        result.reason = AnchorStateReason::InvalidCommitParent;
        result.action = AnchorStateAction::AbortWrite;
        result.detail =
            std::string("prepared Commit verification failed: ") + error.what();
        return result;
      }
      active_prepared_write = true;
    } else if (prepared.new_head == graph.tip &&
               is_observed_ancestor(graph, prepared.previous_head, graph.tip)) {
      const bool matching_proposal = std::any_of(
          graph.proposals.begin(), graph.proposals.end(),
          [&](const auto& entry) {
            return proposal_matches_prepared(entry.second, prepared) &&
                   graph.observed_proposals.count(entry.first) != 0;
          });
      if (!matching_proposal) {
        result.state = AnchorClientState::RecoveryRequired;
        result.reason = AnchorStateReason::MissingReference;
        result.action = AnchorStateAction::Stop;
        result.detail = "completed prepared write has no observed Proposal";
        return result;
      }
      completed_prepared_write = true;
    } else {
      result.state = AnchorClientState::RecoveryRequired;
      result.reason = AnchorStateReason::PreparedWriteAhead;
      result.action = AnchorStateAction::AbortWrite;
      result.detail = "prepared write is not based on the verified channel tip";
      return result;
    }
  }

  const auto cloud_pending = std::find_if(
      graph.proposals.begin(), graph.proposals.end(),
      [&](const auto& entry) {
        return graph.observed_proposals.count(entry.first) == 0 &&
               entry.second.new_head == input.cloud_head &&
               is_observed_ancestor(graph, entry.second.previous_head,
                                    graph.tip);
      });

  if (active_prepared_write && input.cloud_head == graph.tip &&
      input.local_head == input.prepared_write->new_head) {
    const bool proposal_published = std::any_of(
        pending_from_tip.begin(), pending_from_tip.end(),
        [&](const auto& entry) {
          return proposal_matches_prepared(entry.second,
                                           *input.prepared_write);
        });
    result.state = proposal_published ? AnchorClientState::Proposed
                                      : AnchorClientState::WritePrepared;
    result.reason = AnchorStateReason::PreparedWriteAhead;
    result.action = AnchorStateAction::RetryPublish;
    result.detail =
        "local HEAD is ahead only because it matches the prepared write";
    return result;
  }

  if (input.cloud_head != graph.tip && cloud_pending != graph.proposals.end()) {
    result.state = AnchorClientState::ObservationRequired;
    result.reason = AnchorStateReason::CloudMatchesPendingProposal;
    result.action = AnchorStateAction::PublishObservation;
    result.proposal_to_observe = cloud_pending->first;
    result.detail = "cloud HEAD matches a Proposal that has no Observation";
    return result;
  }

  if (input.cloud_head == graph.tip && input.local_head == graph.tip) {
    if (completed_prepared_write) {
      result.state = AnchorClientState::Announced;
      result.action = AnchorStateAction::AdoptVerifiedTip;
      result.detail = "Observation is published; local checkpoint can be finalized";
      return result;
    }
    if (active_prepared_write && !pending_from_tip.empty()) {
      result.state = AnchorClientState::Proposed;
      result.action = AnchorStateAction::RetryPublish;
      result.detail = "one or more Proposals await a cloud HEAD observation";
      return result;
    }
    if (active_prepared_write) {
      result.state = AnchorClientState::WritePrepared;
      result.action = AnchorStateAction::RetryPublish;
      result.detail = "Commit is prepared but its Proposal is not published";
      return result;
    }
    result.state = AnchorClientState::Consistent;
    result.detail = "local, cloud, and observed channel tip agree";
    return result;
  }

  if (input.cloud_head == graph.tip &&
      is_observed_ancestor(graph, input.local_head, graph.tip)) {
    result.state = completed_prepared_write
                       ? AnchorClientState::Announced
                       : AnchorClientState::LocalCatchUp;
    result.reason = AnchorStateReason::LocalBehind;
    result.action = AnchorStateAction::AdoptVerifiedTip;
    result.local_head_to_adopt = graph.tip;
    result.detail = "observed channel tip can advance the local HEAD";
    return result;
  }

  if (is_observed_ancestor(graph, input.cloud_head, graph.tip) &&
      input.cloud_head != graph.tip) {
    result.state = AnchorClientState::RollbackDetected;
    result.reason = AnchorStateReason::CloudBehindObservedTip;
    result.action = AnchorStateAction::Stop;
    result.detail = "cloud HEAD is behind the verified observed tip";
    return result;
  }

  try {
    if (is_commit_ancestor(context, graph.tip, input.cloud_head)) {
      result.detail =
          "cloud HEAD is ahead of the observed tip without a matching Proposal";
    } else {
      result.detail =
          "cloud HEAD diverges from the observed tip without a matching Proposal";
    }
  } catch (const std::exception& error) {
    result.detail = std::string("cloud HEAD ancestry verification failed: ") +
                    error.what();
  }
  result.state = AnchorClientState::RecoveryRequired;
  result.reason = AnchorStateReason::UnexplainedCloudHead;
  result.action = AnchorStateAction::Stop;
  return result;
}

const char* anchor_client_state_name(AnchorClientState state) {
  switch (state) {
    case AnchorClientState::Consistent:
      return "CONSISTENT";
    case AnchorClientState::LocalCatchUp:
      return "LOCAL_CATCH_UP";
    case AnchorClientState::WritePrepared:
      return "WRITE_PREPARED";
    case AnchorClientState::Proposed:
      return "PROPOSED";
    case AnchorClientState::ObservationRequired:
      return "OBSERVATION_REQUIRED";
    case AnchorClientState::Announced:
      return "ANNOUNCED";
    case AnchorClientState::DegradedReadOnly:
      return "DEGRADED_READ_ONLY";
    case AnchorClientState::RollbackDetected:
      return "ROLLBACK_DETECTED";
    case AnchorClientState::Forked:
      return "FORKED";
    case AnchorClientState::RecoveryRequired:
      return "RECOVERY_REQUIRED";
  }
  return "UNKNOWN";
}

const char* anchor_state_reason_name(AnchorStateReason reason) {
  switch (reason) {
    case AnchorStateReason::None:
      return "NONE";
    case AnchorStateReason::LocalBehind:
      return "LOCAL_BEHIND";
    case AnchorStateReason::CloudBehindObservedTip:
      return "CLOUD_BEHIND_OBSERVED_TIP";
    case AnchorStateReason::CloudMatchesPendingProposal:
      return "CLOUD_MATCHES_PENDING_PROPOSAL";
    case AnchorStateReason::UnexplainedCloudHead:
      return "UNEXPLAINED_CLOUD_HEAD";
    case AnchorStateReason::DivergentObservedBranches:
      return "DIVERGENT_OBSERVED_BRANCHES";
    case AnchorStateReason::IncompleteRelaySync:
      return "INCOMPLETE_RELAY_SYNC";
    case AnchorStateReason::InvalidCommitParent:
      return "INVALID_COMMIT_PARENT";
    case AnchorStateReason::MissingReference:
      return "MISSING_REFERENCE";
    case AnchorStateReason::PreparedWriteAhead:
      return "PREPARED_WRITE_AHEAD";
    case AnchorStateReason::InvalidEventGraph:
      return "INVALID_EVENT_GRAPH";
  }
  return "UNKNOWN";
}

const char* anchor_state_action_name(AnchorStateAction action) {
  switch (action) {
    case AnchorStateAction::None:
      return "NONE";
    case AnchorStateAction::AdoptVerifiedTip:
      return "ADOPT_VERIFIED_TIP";
    case AnchorStateAction::PublishObservation:
      return "PUBLISH_OBSERVATION";
    case AnchorStateAction::RetryPublish:
      return "RETRY_PUBLISH";
    case AnchorStateAction::AbortWrite:
      return "ABORT_WRITE";
    case AnchorStateAction::Stop:
      return "STOP";
  }
  return "UNKNOWN";
}
