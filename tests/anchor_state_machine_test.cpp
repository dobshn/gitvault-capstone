#include "anchor_event.h"
#include "anchor_state_machine.h"
#include "local_file_anchor_channel.h"
#include "util.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace {

int failures = 0;

struct TempDirectory {
  std::filesystem::path path;

  TempDirectory()
      : path(std::filesystem::temp_directory_path() /
             ("gitvault-state-test-" + to_hex(random_bytes(8)))) {}

  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

struct FakeCommitStore {
  std::map<AnchorHash, AnchorHash> parents;

  bool verify(const AnchorHash& commit, const AnchorHash& parent) const {
    const auto stored = parents.find(commit);
    return stored != parents.end() && stored->second == parent;
  }

  bool is_ancestor(const AnchorHash& ancestor,
                   const AnchorHash& descendant) const {
    AnchorHash current = descendant;
    std::set<AnchorHash> visited;
    while (visited.insert(current).second) {
      if (current == ancestor) {
        return true;
      }
      const auto stored = parents.find(current);
      if (stored == parents.end() || stored->second == AnchorHash{}) {
        return false;
      }
      current = stored->second;
    }
    return false;
  }
};

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    failures++;
  }
}

void expect_state(const AnchorStateResult& result,
                  AnchorClientState expected,
                  const std::string& message) {
  if (result.state != expected) {
    std::cerr << "FAIL: " << message << " expected "
              << anchor_client_state_name(expected) << " but got "
              << anchor_client_state_name(result.state) << " ("
              << result.detail << ")\n";
    failures++;
  }
}

void expect_throw(const std::function<void()>& action,
                  const std::string& expected_message,
                  const std::string& test_name) {
  try {
    action();
    std::cerr << "FAIL: " << test_name << " did not throw\n";
    failures++;
  } catch (const std::runtime_error& error) {
    if (std::string(error.what()).find(expected_message) == std::string::npos) {
      std::cerr << "FAIL: " << test_name
                << " threw unexpected error: " << error.what() << "\n";
      failures++;
    }
  }
}

template <size_t N>
std::array<uint8_t, N> filled(uint8_t value) {
  std::array<uint8_t, N> result{};
  result.fill(value);
  return result;
}

std::array<uint8_t, 32> signing_secret(uint8_t value) {
  std::array<uint8_t, 32> secret{};
  secret.back() = value;
  return secret;
}

AnchorEventCommon common(const AnchorHash& vault_id,
                         const AnchorOperationId& operation_id,
                         const std::string& installation_id) {
  AnchorEventCommon value;
  value.vault_id = vault_id;
  value.operation_id = operation_id;
  value.protocol_epoch = 7;
  value.installation_id = installation_id;
  return value;
}

struct Scenario {
  std::array<uint8_t, 32> secret = signing_secret(3);
  AnchorHash vault_id = filled<32>(0x11);
  AnchorHash config_hash = filled<32>(0x22);
  AnchorHash h0 = filled<32>(0x30);
  AnchorHash h1 = filled<32>(0x31);
  AnchorHash h2 = filled<32>(0x32);
  AnchorHash h3 = filled<32>(0x33);
  AnchorHash hx = filled<32>(0x7f);
  AnchorOperationId op1 = filled<16>(0x41);
  AnchorOperationId op2 = filled<16>(0x42);
  std::vector<NostrTag> tags = {{"channel", "state-test"}};
  FakeCommitStore commits;
  SignedNostrEvent genesis;

  Scenario() {
    commits.parents[h0] = AnchorHash{};
    commits.parents[h1] = h0;
    commits.parents[h2] = h0;
    commits.parents[h3] = h1;

    VaultGenesisEvent payload;
    payload.common = common(vault_id, filled<16>(0x40), "device-a");
    payload.config_hash = config_hash;
    payload.initial_head = h0;
    genesis = sign_anchor_event(payload, 100, tags, secret);
  }

  HeadProposalEvent proposal_payload(const AnchorOperationId& operation,
                                     const AnchorHash& next_head,
                                     const AnchorHash& parent_event_id) const {
    HeadProposalEvent payload;
    payload.common = common(vault_id, operation, "device-a");
    payload.previous_head = h0;
    payload.new_head = next_head;
    payload.parent_event_id = parent_event_id;
    return payload;
  }

  SignedNostrEvent proposal(const AnchorOperationId& operation,
                            const AnchorHash& next_head,
                            const AnchorHash& parent_event_id,
                            uint64_t created_at = 200) const {
    return sign_anchor_event(
        proposal_payload(operation, next_head, parent_event_id),
        created_at, tags, secret);
  }

  SignedNostrEvent observation(const AnchorOperationId& operation,
                               const SignedNostrEvent& proposal_event,
                               const AnchorHash& previous_head,
                               const AnchorHash& observed_head,
                               uint64_t created_at = 300,
                               const std::string& installation = "device-a") const {
    HeadObservationEvent payload;
    payload.common = common(vault_id, operation, installation);
    payload.proposal_event_id = proposal_event.id;
    payload.expected_previous_head = previous_head;
    payload.observed_cloud_head = observed_head;
    payload.observed_cloud_revision = "rev-1";
    return sign_anchor_event(payload, created_at, tags, secret);
  }

  AnchorStateContext context() const {
    AnchorStateContext value;
    value.trusted_public_key = schnorr_public_key(secret);
    value.expected_vault_id = vault_id;
    value.expected_config_hash = config_hash;
    value.expected_protocol_epoch = 7;
    value.genesis_event_id = genesis.id;
    value.verify_commit_parent = [this](const AnchorHash& commit,
                                        const AnchorHash& parent) {
      return commits.verify(commit, parent);
    };
    value.is_commit_ancestor = [this](const AnchorHash& ancestor,
                                      const AnchorHash& descendant) {
      return commits.is_ancestor(ancestor, descendant);
    };
    return value;
  }
};

AnchorStateResult evaluate(const Scenario& scenario,
                           const LocalFileAnchorChannel& channel,
                           const AnchorHash& local_head,
                           const AnchorHash& cloud_head,
                           const std::optional<PreparedHeadTransition>& prepared =
                               std::nullopt,
                           bool synchronized = true) {
  AnchorStateInput input;
  input.events = channel.fetch().events;
  input.local_head = local_head;
  input.cloud_head = cloud_head;
  input.prepared_write = prepared;
  input.channel_synchronized = synchronized;
  return evaluate_anchor_state(scenario.context(), input);
}

void test_payload_round_trip_and_canonical_requirement() {
  Scenario scenario;
  const HeadProposalEvent proposal = scenario.proposal_payload(
      scenario.op1, scenario.h1, scenario.genesis.id);
  const std::string encoded = serialize_anchor_event_payload(proposal);
  const AnchorEventPayload decoded = deserialize_anchor_event_payload(encoded);
  const auto* decoded_proposal = std::get_if<HeadProposalEvent>(&decoded);

  expect(decoded_proposal != nullptr &&
             decoded_proposal->common.vault_id == scenario.vault_id &&
             decoded_proposal->common.operation_id == scenario.op1 &&
             decoded_proposal->previous_head == scenario.h0 &&
             decoded_proposal->new_head == scenario.h1 &&
             decoded_proposal->parent_event_id == scenario.genesis.id,
         "Proposal semantic fields round-trip through canonical JSON");

  const std::string noncanonical = "{ " + encoded.substr(1);
  expect_throw(
      [&] { (void)deserialize_anchor_event_payload(noncanonical); },
      "not canonical JSON", "non-canonical anchor payload");

  const std::string unknown_field = "{\"extra\":0," + encoded.substr(1);
  expect_throw(
      [&] { (void)deserialize_anchor_event_payload(unknown_field); },
      "fields do not match", "unknown anchor payload field");
}

void test_encrypted_anchor_event_verifies_before_decryption() {
  Scenario scenario;
  const HeadProposalEvent proposal = scenario.proposal_payload(
      scenario.op1, scenario.h1, scenario.genesis.id);
  const SignedNostrEvent encrypted = sign_encrypted_anchor_event(
      proposal, 1234, {{"t", std::string(64, 'a')}}, scenario.secret);
  expect(encrypted.content.find("head_proposal") == std::string::npos &&
             encrypted.content.find(to_hex(scenario.h1)) == std::string::npos,
         "encrypted Nostr content does not expose Proposal semantics or HEAD");
  const AnchorEventPayload decoded = verify_decrypt_anchor_event(
      encrypted, schnorr_public_key(scenario.secret), scenario.secret);
  const auto* decoded_proposal = std::get_if<HeadProposalEvent>(&decoded);
  expect(decoded_proposal != nullptr &&
             decoded_proposal->new_head == scenario.h1,
         "verified encrypted event decrypts to the canonical Proposal");

  SignedNostrEvent tampered = encrypted;
  tampered.content[tampered.content.size() / 2] =
      tampered.content[tampered.content.size() / 2] == 'A' ? 'B' : 'A';
  expect_throw(
      [&] {
        (void)verify_decrypt_anchor_event(
            tampered, schnorr_public_key(scenario.secret), scenario.secret);
      },
      "signature verification failed",
      "outer signature is checked before decrypting modified content");
}

void test_fault_injection_across_write_boundaries() {
  Scenario scenario;
  TempDirectory temp;
  LocalFileAnchorChannel channel(temp.path);
  channel.publish(scenario.genesis);

  const PreparedHeadTransition prepared{
      scenario.op1, scenario.h0, scenario.h1};
  expect_state(evaluate(scenario, channel, scenario.h0, scenario.h0),
               AnchorClientState::Consistent,
               "before write, all three HEAD views agree");
  expect_state(evaluate(scenario, channel, scenario.h0, scenario.h0, prepared),
               AnchorClientState::WritePrepared,
               "crash after Commit preparation is recoverable as WRITE_PREPARED");

  const SignedNostrEvent proposal = scenario.proposal(
      scenario.op1, scenario.h1, scenario.genesis.id);
  channel.publish(proposal);
  expect_state(evaluate(scenario, channel, scenario.h0, scenario.h0, prepared),
               AnchorClientState::Proposed,
               "crash after Proposal publish is recovered as PROPOSED");

  const AnchorStateResult head_updated =
      evaluate(scenario, channel, scenario.h0, scenario.h1, prepared);
  expect_state(head_updated, AnchorClientState::ObservationRequired,
               "crash after cloud CAS requires an Observation");
  expect(head_updated.proposal_to_observe == proposal.id,
         "OBSERVATION_REQUIRED identifies the Proposal to recover");

  const SignedNostrEvent observation = scenario.observation(
      scenario.op1, proposal, scenario.h0, scenario.h1);
  channel.publish(observation);
  const AnchorStateResult announced =
      evaluate(scenario, channel, scenario.h0, scenario.h1, prepared);
  expect_state(announced, AnchorClientState::Announced,
               "crash after Observation publish is recovered as ANNOUNCED");
  expect(announced.local_head_to_adopt == scenario.h1,
         "ANNOUNCED identifies the verified tip for local checkpoint update");

  expect_state(evaluate(scenario, channel, scenario.h1, scenario.h1, prepared),
               AnchorClientState::Announced,
               "durable prepared record keeps completion in ANNOUNCED");
  expect_state(evaluate(scenario, channel, scenario.h1, scenario.h1),
               AnchorClientState::Consistent,
               "clearing the completed record finalizes CONSISTENT");
}

void test_two_proposals_are_not_a_fork_until_both_are_observed() {
  Scenario scenario;
  TempDirectory temp;
  LocalFileAnchorChannel channel(temp.path);
  channel.publish(scenario.genesis);
  const SignedNostrEvent first = scenario.proposal(
      scenario.op1, scenario.h1, scenario.genesis.id, 500);
  const SignedNostrEvent second = scenario.proposal(
      scenario.op2, scenario.h2, scenario.genesis.id, 400);
  channel.publish(first);
  channel.publish(second);
  channel.publish(scenario.observation(
      scenario.op1, first, scenario.h0, scenario.h1, 300));

  const AnchorStateResult one_observed =
      evaluate(scenario, channel, scenario.h0, scenario.h1);
  expect_state(one_observed, AnchorClientState::LocalCatchUp,
               "one observed branch and one pending Proposal are not a fork");
  expect(one_observed.pending_proposal_event_ids.size() == 1,
         "the losing concurrent Proposal remains visible as pending evidence");

  channel.publish(scenario.observation(
      scenario.op1, first, scenario.h0, scenario.h1, 250, "device-b"));
  const AnchorStateResult duplicate_observation =
      evaluate(scenario, channel, scenario.h0, scenario.h1);
  expect_state(duplicate_observation, AnchorClientState::LocalCatchUp,
               "two Observations of the same edge do not create a fork");
  expect(duplicate_observation.valid_observation_event_ids.size() == 2,
         "both equivalent Observations remain visible as evidence");

  channel.publish(scenario.observation(
      scenario.op2, second, scenario.h0, scenario.h2, 200, "device-b"));
  const AnchorStateResult forked =
      evaluate(scenario, channel, scenario.h1, scenario.h1);
  expect_state(forked, AnchorClientState::Forked,
               "two observed children of one HEAD produce FORKED");
  expect(forked.fork_heads.size() == 2,
         "both conflicting observed HEADs are reported");
}

void test_missing_references_and_invalid_commit_require_recovery() {
  Scenario missing_proposal_scenario;
  TempDirectory missing_proposal_temp;
  LocalFileAnchorChannel missing_proposal_channel(missing_proposal_temp.path);
  missing_proposal_channel.publish(missing_proposal_scenario.genesis);
  const SignedNostrEvent unpublished_proposal =
      missing_proposal_scenario.proposal(
          missing_proposal_scenario.op1,
          missing_proposal_scenario.h1,
          missing_proposal_scenario.genesis.id);
  missing_proposal_channel.publish(missing_proposal_scenario.observation(
      missing_proposal_scenario.op1, unpublished_proposal,
      missing_proposal_scenario.h0, missing_proposal_scenario.h1));
  expect_state(
      evaluate(missing_proposal_scenario, missing_proposal_channel,
               missing_proposal_scenario.h0, missing_proposal_scenario.h0),
      AnchorClientState::RecoveryRequired,
      "Observation without its Proposal requires recovery");

  Scenario bad_commit_scenario;
  bad_commit_scenario.commits.parents[bad_commit_scenario.h1] =
      bad_commit_scenario.h2;
  TempDirectory bad_commit_temp;
  LocalFileAnchorChannel bad_commit_channel(bad_commit_temp.path);
  bad_commit_channel.publish(bad_commit_scenario.genesis);
  bad_commit_channel.publish(bad_commit_scenario.proposal(
      bad_commit_scenario.op1, bad_commit_scenario.h1,
      bad_commit_scenario.genesis.id));
  expect_state(
      evaluate(bad_commit_scenario, bad_commit_channel,
               bad_commit_scenario.h0, bad_commit_scenario.h0),
      AnchorClientState::RecoveryRequired,
      "Proposal whose Commit has a different parent requires recovery");

  Scenario bad_observation_scenario;
  TempDirectory bad_observation_temp;
  LocalFileAnchorChannel bad_observation_channel(bad_observation_temp.path);
  bad_observation_channel.publish(bad_observation_scenario.genesis);
  const SignedNostrEvent valid_proposal = bad_observation_scenario.proposal(
      bad_observation_scenario.op1, bad_observation_scenario.h1,
      bad_observation_scenario.genesis.id);
  bad_observation_channel.publish(valid_proposal);
  bad_observation_channel.publish(bad_observation_scenario.observation(
      bad_observation_scenario.op1, valid_proposal,
      bad_observation_scenario.h0, bad_observation_scenario.h2));
  expect_state(
      evaluate(bad_observation_scenario, bad_observation_channel,
               bad_observation_scenario.h0, bad_observation_scenario.h0),
      AnchorClientState::RecoveryRequired,
      "Observation that claims a different HEAD than its Proposal is rejected");

  Scenario bad_genesis_scenario;
  bad_genesis_scenario.commits.parents.erase(bad_genesis_scenario.h0);
  TempDirectory bad_genesis_temp;
  LocalFileAnchorChannel bad_genesis_channel(bad_genesis_temp.path);
  bad_genesis_channel.publish(bad_genesis_scenario.genesis);
  expect_state(
      evaluate(bad_genesis_scenario, bad_genesis_channel,
               bad_genesis_scenario.h0, bad_genesis_scenario.h0),
      AnchorClientState::RecoveryRequired,
      "Genesis whose initial Commit is missing requires recovery");
}

void test_untrusted_events_are_rejected_without_poisoning_valid_history() {
  Scenario scenario;
  TempDirectory temp;
  LocalFileAnchorChannel channel(temp.path);
  channel.publish(scenario.genesis);

  HeadProposalEvent attacker_payload = scenario.proposal_payload(
      scenario.op1, scenario.h1, scenario.genesis.id);
  const SignedNostrEvent attacker = sign_anchor_event(
      attacker_payload, 200, scenario.tags, signing_secret(4));
  channel.publish(attacker);

  const AnchorStateResult result =
      evaluate(scenario, channel, scenario.h0, scenario.h0);
  expect_state(result, AnchorClientState::Consistent,
               "foreign self-signed event does not poison valid history");
  expect(result.rejected_event_ids.size() == 1,
         "the foreign event remains visible in rejection diagnostics");
}

void test_rollback_unknown_cloud_and_channel_failure_are_fail_closed() {
  Scenario scenario;
  TempDirectory temp;
  LocalFileAnchorChannel channel(temp.path);
  channel.publish(scenario.genesis);
  const SignedNostrEvent proposal = scenario.proposal(
      scenario.op1, scenario.h1, scenario.genesis.id);
  channel.publish(proposal);
  channel.publish(scenario.observation(
      scenario.op1, proposal, scenario.h0, scenario.h1));

  expect_state(evaluate(scenario, channel, scenario.h1, scenario.h0),
               AnchorClientState::RollbackDetected,
               "cloud rollback behind the observed tip fails closed");
  expect_state(evaluate(scenario, channel, scenario.h1, scenario.hx),
               AnchorClientState::RecoveryRequired,
               "unexplained cloud HEAD fails closed");
  expect_state(evaluate(scenario, channel, scenario.h1, scenario.h1,
                        std::nullopt, false),
               AnchorClientState::RecoveryRequired,
               "incomplete channel synchronization fails closed");
}

void test_replay_and_created_at_order_do_not_change_the_graph() {
  Scenario scenario;
  const SignedNostrEvent first_proposal = scenario.proposal(
      scenario.op1, scenario.h1, scenario.genesis.id, 900);
  const SignedNostrEvent first_observation = scenario.observation(
      scenario.op1, first_proposal, scenario.h0, scenario.h1, 1);

  HeadProposalEvent second_payload;
  second_payload.common =
      common(scenario.vault_id, scenario.op2, "device-b");
  second_payload.previous_head = scenario.h1;
  second_payload.new_head = scenario.h3;
  second_payload.parent_event_id = first_observation.id;
  const SignedNostrEvent second_proposal = sign_anchor_event(
      second_payload, 800, scenario.tags, scenario.secret);
  const SignedNostrEvent second_observation = scenario.observation(
      scenario.op2, second_proposal, scenario.h1, scenario.h3, 2,
      "device-b");

  AnchorStateInput input;
  input.events = {
      second_observation, second_proposal, first_observation,
      first_proposal, scenario.genesis, second_observation,
      first_proposal, scenario.genesis,
  };
  input.local_head = scenario.h3;
  input.cloud_head = scenario.h3;
  const AnchorStateResult result =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(result, AnchorClientState::Consistent,
               "event references, not timestamps or delivery order, define history");
  expect(result.verified_tip == scenario.h3 &&
             result.valid_proposal_event_ids.size() == 2 &&
             result.valid_observation_event_ids.size() == 2,
         "replayed event IDs are deduplicated");
}

void test_linear_head_relation_matrix_and_reasons() {
  Scenario scenario;
  const SignedNostrEvent first_proposal = scenario.proposal(
      scenario.op1, scenario.h1, scenario.genesis.id);
  const SignedNostrEvent first_observation = scenario.observation(
      scenario.op1, first_proposal, scenario.h0, scenario.h1);
  HeadProposalEvent second_payload;
  second_payload.common = common(scenario.vault_id, scenario.op2, "device-a");
  second_payload.previous_head = scenario.h1;
  second_payload.new_head = scenario.h3;
  second_payload.parent_event_id = first_observation.id;
  const SignedNostrEvent second_proposal = sign_anchor_event(
      second_payload, 400, scenario.tags, scenario.secret);
  const SignedNostrEvent second_observation = scenario.observation(
      scenario.op2, second_proposal, scenario.h1, scenario.h3, 500);

  AnchorStateInput input;
  input.events = {scenario.genesis, first_proposal, first_observation,
                  second_proposal, second_observation};
  const std::vector<AnchorHash> linear = {
      scenario.h0, scenario.h1, scenario.h3};
  for (size_t local_index = 0; local_index < linear.size(); ++local_index) {
    for (size_t cloud_index = 0; cloud_index < linear.size(); ++cloud_index) {
      input.local_head = linear[local_index];
      input.cloud_head = linear[cloud_index];
      const AnchorStateResult result =
          evaluate_anchor_state(scenario.context(), input);
      if (cloud_index == 2) {
        expect_state(result,
                     local_index == 2 ? AnchorClientState::Consistent
                                      : AnchorClientState::LocalCatchUp,
                     "C=N is consistent or safely catches up L");
      } else {
        expect_state(result, AnchorClientState::RollbackDetected,
                     "every C<N linear combination is rollback");
        expect(result.reason == AnchorStateReason::CloudBehindObservedTip,
               "rollback has a distinct CLOUD_BEHIND_OBSERVED_TIP reason");
      }
    }
  }

  input.local_head = scenario.h2;
  input.cloud_head = scenario.h3;
  expect_state(evaluate_anchor_state(scenario.context(), input),
               AnchorClientState::RecoveryRequired,
               "L parallel to N is not silently replaced");

  input.local_head = scenario.h3;
  input.cloud_head = scenario.h1;
  const AnchorStateResult rollback =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(rollback, AnchorClientState::RollbackDetected,
               "local-ahead view still diagnoses C<N as rollback");
}

void test_unobserved_ahead_and_parallel_proposals() {
  Scenario scenario;
  const SignedNostrEvent first = scenario.proposal(
      scenario.op1, scenario.h1, scenario.genesis.id);
  const SignedNostrEvent first_observation = scenario.observation(
      scenario.op1, first, scenario.h0, scenario.h1);

  AnchorStateInput input;
  input.events = {scenario.genesis, first, first_observation};
  input.local_head = scenario.h1;
  input.cloud_head = scenario.h3;
  const AnchorStateResult unexplained =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(unexplained, AnchorClientState::RecoveryRequired,
               "N<C without a Proposal is unexplained");
  expect(unexplained.reason == AnchorStateReason::UnexplainedCloudHead,
         "unexplained N<C is not labeled as Nostr delay");

  HeadProposalEvent ahead_payload;
  ahead_payload.common = common(scenario.vault_id, scenario.op2, "device-b");
  ahead_payload.previous_head = scenario.h1;
  ahead_payload.new_head = scenario.h3;
  ahead_payload.parent_event_id = first_observation.id;
  const SignedNostrEvent ahead = sign_anchor_event(
      ahead_payload, 600, scenario.tags, scenario.secret);
  input.events.push_back(ahead);
  const AnchorStateResult explained =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(explained, AnchorClientState::ObservationRequired,
               "N<C with the exact Proposal requires Observation");
  expect(explained.reason == AnchorStateReason::CloudMatchesPendingProposal &&
             explained.proposal_to_observe == ahead.id,
         "the matching Proposal is identified for recovery");

  Scenario parallel;
  const SignedNostrEvent left = parallel.proposal(
      parallel.op1, parallel.h1, parallel.genesis.id);
  const SignedNostrEvent right = parallel.proposal(
      parallel.op2, parallel.h2, parallel.genesis.id);
  input.events = {parallel.genesis, left, right,
                  parallel.observation(parallel.op1, left,
                                       parallel.h0, parallel.h1)};
  input.local_head = parallel.h1;
  input.cloud_head = parallel.h2;
  const AnchorStateResult parallel_proposal =
      evaluate_anchor_state(parallel.context(), input);
  expect_state(parallel_proposal, AnchorClientState::ObservationRequired,
               "C parallel to N with a valid Proposal is observed first");
  input.events.push_back(parallel.observation(
      parallel.op2, right, parallel.h0, parallel.h2));
  const AnchorStateResult fork =
      evaluate_anchor_state(parallel.context(), input);
  expect_state(fork, AnchorClientState::Forked,
               "two observed parallel branches become a fork");
  expect(fork.reason == AnchorStateReason::DivergentObservedBranches,
         "fork has a distinct DIVERGENT_OBSERVED_BRANCHES reason");
}

void test_incomplete_relay_sync_allows_only_checkpoint_read() {
  Scenario scenario;
  AnchorStateInput input;
  input.events = {scenario.genesis};
  input.local_head = scenario.h0;
  input.cloud_head = scenario.h0;
  input.channel_synchronized = false;
  input.read_only_operation = true;
  input.checkpoint_head = scenario.h0;
  const AnchorStateResult degraded =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(degraded, AnchorClientState::DegradedReadOnly,
               "an incomplete read quorum allows only L=C=checkpoint reads");
  expect(degraded.reason == AnchorStateReason::IncompleteRelaySync,
         "degraded read reports incomplete relay sync");

  input.read_only_operation = false;
  expect_state(evaluate_anchor_state(scenario.context(), input),
               AnchorClientState::RecoveryRequired,
               "an incomplete read quorum always blocks writes");
  input.read_only_operation = true;
  input.cloud_head = scenario.h1;
  expect_state(evaluate_anchor_state(scenario.context(), input),
               AnchorClientState::RecoveryRequired,
               "an incomplete read quorum blocks a divergent cloud read");
}

void test_wrong_channel_tag_is_not_trusted() {
  Scenario scenario;
  AnchorStateContext context = scenario.context();
  context.expected_channel_tag = std::string(64, 'a');
  AnchorStateInput input;
  input.events = {scenario.genesis};
  input.local_head = scenario.h0;
  input.cloud_head = scenario.h0;
  const AnchorStateResult result = evaluate_anchor_state(context, input);
  expect_state(result, AnchorClientState::RecoveryRequired,
               "a valid Vault signature on the wrong channel tag is unusable");
  expect(result.reason == AnchorStateReason::MissingReference,
         "wrong channel Genesis leaves the pinned reference missing");
}

void test_local_ahead_is_recoverable_only_with_matching_prepared_write() {
  Scenario scenario;
  AnchorStateInput input;
  input.events = {scenario.genesis};
  input.local_head = scenario.h1;
  input.cloud_head = scenario.h0;
  const AnchorStateResult unexplained =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(unexplained, AnchorClientState::RecoveryRequired,
               "L>N without a journal fails closed");

  input.prepared_write = PreparedHeadTransition{
      scenario.op1, scenario.h0, scenario.h1};
  const AnchorStateResult journaled =
      evaluate_anchor_state(scenario.context(), input);
  expect_state(journaled, AnchorClientState::WritePrepared,
               "L>N matching W resumes the journaled transition");
  expect(journaled.reason == AnchorStateReason::PreparedWriteAhead,
         "matching W is explicit in the decision reason");
}

}  // namespace

int main() {
  test_payload_round_trip_and_canonical_requirement();
  test_encrypted_anchor_event_verifies_before_decryption();
  test_fault_injection_across_write_boundaries();
  test_two_proposals_are_not_a_fork_until_both_are_observed();
  test_missing_references_and_invalid_commit_require_recovery();
  test_untrusted_events_are_rejected_without_poisoning_valid_history();
  test_rollback_unknown_cloud_and_channel_failure_are_fail_closed();
  test_replay_and_created_at_order_do_not_change_the_graph();
  test_linear_head_relation_matrix_and_reasons();
  test_unobserved_ahead_and_parallel_proposals();
  test_incomplete_relay_sync_allows_only_checkpoint_read();
  test_wrong_channel_tag_is_not_trusted();
  test_local_ahead_is_recoverable_only_with_matching_prepared_write();

  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all anchor state machine tests passed\n";
  return 0;
}
