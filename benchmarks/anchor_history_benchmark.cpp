#include "anchor_event.h"
#include "anchor_state_machine.h"
#include "crypto/sha256.h"
#include "util.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {
AnchorHash hash_label(const std::string& label) {
  return Sha256::hash(ByteVec(label.begin(), label.end()));
}

AnchorOperationId operation_id(size_t index) {
  AnchorOperationId result{};
  for (size_t i = 0; i < sizeof(index); ++i) {
    result[result.size() - 1 - i] =
        static_cast<uint8_t>((index >> (i * 8)) & 0xff);
  }
  return result;
}

AnchorEventCommon common(const AnchorHash& vault,
                         const AnchorOperationId& operation) {
  AnchorEventCommon result;
  result.vault_id = vault;
  result.operation_id = operation;
  result.installation_id = "benchmark";
  return result;
}

double percentile(std::vector<double> values, double fraction) {
  std::sort(values.begin(), values.end());
  const size_t index = std::min(
      values.size() - 1,
      static_cast<size_t>(fraction * static_cast<double>(values.size())));
  return values[index];
}

void run(size_t commit_count) {
  std::array<uint8_t, 32> secret{};
  secret.back() = 3;
  const AnchorHash vault = hash_label("benchmark-vault");
  const AnchorHash config = hash_label("benchmark-config");
  std::map<AnchorHash, AnchorHash> parents;
  std::vector<SignedNostrEvent> events;
  std::vector<NostrTag> tags = {{"t", std::string(64, 'a')}};

  AnchorHash head = hash_label("head-0");
  parents[head] = {};
  VaultGenesisEvent genesis;
  genesis.common = common(vault, operation_id(0));
  genesis.config_hash = config;
  genesis.initial_head = head;
  SignedNostrEvent parent_event = sign_anchor_event(
      genesis, 0, tags, secret);
  events.push_back(parent_event);

  for (size_t index = 1; index <= commit_count; ++index) {
    const AnchorHash next = hash_label("head-" + std::to_string(index));
    parents[next] = head;
    HeadProposalEvent proposal;
    proposal.common = common(vault, operation_id(index));
    proposal.previous_head = head;
    proposal.new_head = next;
    proposal.parent_event_id = parent_event.id;
    const SignedNostrEvent proposal_event = sign_anchor_event(
        proposal, index * 2, tags, secret);
    events.push_back(proposal_event);

    HeadObservationEvent observation;
    observation.common = proposal.common;
    observation.proposal_event_id = proposal_event.id;
    observation.expected_previous_head = head;
    observation.observed_cloud_head = next;
    observation.observed_cloud_revision =
        "rev-" + std::to_string(index);
    parent_event = sign_anchor_event(
        observation, index * 2 + 1, tags, secret);
    events.push_back(parent_event);
    head = next;
  }

  AnchorStateContext context;
  context.trusted_public_key = schnorr_public_key(secret);
  context.expected_vault_id = vault;
  context.expected_config_hash = config;
  context.expected_protocol_epoch = 0;
  context.genesis_event_id = events.front().id;
  context.verify_commit_parent = [&](const AnchorHash& commit,
                                     const AnchorHash& expected) {
    const auto found = parents.find(commit);
    return found != parents.end() && found->second == expected;
  };
  context.is_commit_ancestor = [&](const AnchorHash& ancestor,
                                   const AnchorHash& descendant) {
    AnchorHash current = descendant;
    std::set<AnchorHash> visited;
    while (visited.insert(current).second) {
      if (current == ancestor) return true;
      const auto found = parents.find(current);
      if (found == parents.end() || found->second == AnchorHash{}) return false;
      current = found->second;
    }
    return false;
  };
  AnchorStateInput input;
  input.events = events;
  input.local_head = head;
  input.cloud_head = head;

  size_t wire_bytes = 0;
  for (const auto& event : events) {
    wire_bytes += serialize_nostr_event_json(event).size();
  }
  std::vector<double> samples;
  for (size_t trial = 0; trial < 7; ++trial) {
    const auto start = std::chrono::steady_clock::now();
    const AnchorStateResult result = evaluate_anchor_state(context, input);
    const auto end = std::chrono::steady_clock::now();
    if (result.state != AnchorClientState::Consistent) {
      throw std::runtime_error("benchmark graph did not validate");
    }
    samples.push_back(std::chrono::duration<double, std::milli>(end - start)
                          .count());
  }
  std::cout << commit_count << ',' << events.size() << ',' << wire_bytes << ','
            << percentile(samples, 0.50) << ','
            << percentile(samples, 0.95) << '\n';
}
}  // namespace

int main(int argc, char** argv) {
  try {
    std::cout << "commits,events,wire_bytes,verify_p50_ms,verify_p95_ms\n";
    if (argc > 1) {
      for (int index = 1; index < argc; ++index) {
        run(static_cast<size_t>(std::stoul(argv[index])));
      }
    } else {
      for (const size_t commits : {1u, 10u, 100u, 1000u}) run(commits);
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "benchmark error: " << error.what() << '\n';
    return 1;
  }
}
