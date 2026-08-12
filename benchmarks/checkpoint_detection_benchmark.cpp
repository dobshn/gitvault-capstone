#include "anchor_event.h"
#include "checkpoint_state_machine.h"
#include "crypto/sha256.h"
#include "util.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
template <size_t N>
std::array<uint8_t, N> filled(uint8_t value) {
  std::array<uint8_t, N> result{};
  result.fill(value);
  return result;
}

SignedNostrEvent checkpoint_event(
    const AnchorHash& vault_id,
    const AnchorHash& channel_id,
    const ReplicaId& replica_id,
    const AnchorHash& head,
    const VectorClock& clock,
    uint64_t created_at,
    const std::array<uint8_t, 32>& secret) {
  const std::string installation =
      to_hex(ByteVec(replica_id.begin(), replica_id.end()));
  HeadCheckpointEvent payload;
  payload.common.vault_id = vault_id;
  payload.common.operation_id = filled<16>(static_cast<uint8_t>(created_at));
  payload.common.installation_id = installation;
  payload.head = head;
  payload.clock = clock;
  payload.head_envelope_hash = filled<32>(static_cast<uint8_t>(created_at));
  payload.observed_cloud_revision = "benchmark-revision";
  return sign_encrypted_anchor_event(
      payload, created_at,
      {{"t", to_hex(channel_id)},
       {"d", "gitvault:" + to_hex(vault_id) + ":" + installation}},
      secret);
}

CheckpointStateInput base_input(const AnchorHash& trusted_head,
                                const VectorClock& trusted_clock) {
  CheckpointStateInput input;
  input.local_checkpoint.accepted_head = trusted_head;
  input.local_checkpoint.accepted_clock = trusted_clock;
  input.local_head.head = trusted_head;
  input.local_head.clock = trusted_clock;
  input.cloud_head.head = trusted_head;
  input.cloud_head.clock = trusted_clock;
  input.channel_synchronized = true;
  return input;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const size_t repetitions = argc == 2
        ? static_cast<size_t>(std::stoul(argv[1])) : 5;
    if (repetitions == 0) throw std::runtime_error("repetitions must be positive");

    std::array<uint8_t, 32> secret{};
    secret.back() = 7;
    const SchnorrPublicKey public_key = schnorr_public_key(secret);
    const AnchorHash vault_id = filled<32>(0x31);
    const AnchorHash channel_id = filled<32>(0x32);
    const AnchorHash old_head = filled<32>(0x40);
    const AnchorHash head_a = filled<32>(0x41);
    const AnchorHash head_b = filled<32>(0x42);
    const ReplicaId replica_a = filled<16>(0xa1);
    const ReplicaId replica_b = filled<16>(0xb2);
    const VectorClock clock_a{{replica_a, 1}};
    const VectorClock clock_b{{replica_b, 1}};
    const SignedNostrEvent event_a = checkpoint_event(
        vault_id, channel_id, replica_a, head_a, clock_a, 100, secret);
    const SignedNostrEvent event_b = checkpoint_event(
        vault_id, channel_id, replica_b, head_b, clock_b, 101, secret);

    AnchorStateContext context;
    context.trusted_public_key = public_key;
    context.expected_vault_id = vault_id;
    context.expected_channel_tag = to_hex(channel_id);
    context.decode_event = [&](const SignedNostrEvent& event) {
      return verify_decrypt_anchor_event(event, public_key, secret);
    };

    // Keep one untimed pass out of the reported sample so process/library
    // initialization does not dominate this in-memory microbenchmark.
    {
      CheckpointStateInput rollback = base_input(head_a, clock_a);
      rollback.cloud_head.head = old_head;
      rollback.cloud_head.clock.clear();
      rollback.witness_events = {event_a};
      if (evaluate_checkpoint_state(context, rollback).state !=
          AnchorClientState::RollbackDetected) {
        throw std::runtime_error("rollback warm-up did not detect rollback");
      }

      CheckpointStateInput fork = base_input(head_a, clock_a);
      fork.witness_events = {event_a, event_b};
      if (evaluate_checkpoint_state(context, fork).state !=
          AnchorClientState::Forked) {
        throw std::runtime_error("fork warm-up did not detect fork");
      }
    }

    std::cout << "scenario,iteration,latency_us,state\n";
    for (size_t iteration = 1; iteration <= repetitions; ++iteration) {
      CheckpointStateInput rollback = base_input(head_a, clock_a);
      rollback.cloud_head.head = old_head;
      rollback.cloud_head.clock.clear();
      rollback.witness_events = {event_a};
      const auto rollback_started = std::chrono::steady_clock::now();
      const AnchorStateResult rollback_result =
          evaluate_checkpoint_state(context, rollback);
      const double rollback_us = std::chrono::duration<double, std::micro>(
          std::chrono::steady_clock::now() - rollback_started).count();
      if (rollback_result.state != AnchorClientState::RollbackDetected) {
        throw std::runtime_error("rollback benchmark did not detect rollback");
      }
      std::cout << "rollback," << iteration << ',' << rollback_us
                << ",ROLLBACK_DETECTED\n";

      CheckpointStateInput fork = base_input(head_a, clock_a);
      fork.witness_events = {event_a, event_b};
      const auto fork_started = std::chrono::steady_clock::now();
      const AnchorStateResult fork_result =
          evaluate_checkpoint_state(context, fork);
      const double fork_us = std::chrono::duration<double, std::micro>(
          std::chrono::steady_clock::now() - fork_started).count();
      if (fork_result.state != AnchorClientState::Forked) {
        throw std::runtime_error("fork benchmark did not detect fork");
      }
      std::cout << "fork," << iteration << ',' << fork_us
                << ",FORKED\n";
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "checkpoint benchmark error: " << error.what() << '\n';
    return 1;
  }
}
