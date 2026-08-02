#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "nostr_event.h"

using AnchorHash = std::array<uint8_t, 32>;
using AnchorOperationId = std::array<uint8_t, 16>;

constexpr uint8_t kAnchorProtocolVersion = 1;
constexpr uint8_t kAnchorCommitFormatVersion = 2;
constexpr uint16_t kGitVaultAnchorEventKind = 9500;

struct AnchorEventCommon {
  uint8_t protocol_version = kAnchorProtocolVersion;
  AnchorHash vault_id{};
  AnchorOperationId operation_id{};
  uint64_t protocol_epoch = 0;
  std::string installation_id;
};

struct VaultGenesisEvent {
  AnchorEventCommon common;
  AnchorHash config_hash{};
  AnchorHash initial_head{};
};

struct HeadProposalEvent {
  AnchorEventCommon common;
  AnchorHash previous_head{};
  AnchorHash new_head{};
  AnchorHash parent_event_id{};
  uint8_t commit_format_version = kAnchorCommitFormatVersion;
};

struct HeadObservationEvent {
  AnchorEventCommon common;
  AnchorHash proposal_event_id{};
  AnchorHash expected_previous_head{};
  AnchorHash observed_cloud_head{};
  std::string observed_cloud_revision;
};

using AnchorEventPayload = std::variant<
    VaultGenesisEvent,
    HeadProposalEvent,
    HeadObservationEvent>;

const AnchorEventCommon& anchor_event_common(const AnchorEventPayload& payload);
std::string serialize_anchor_event_payload(const AnchorEventPayload& payload);
AnchorEventPayload deserialize_anchor_event_payload(
    const std::string& canonical_json);

SignedNostrEvent sign_anchor_event(
    const AnchorEventPayload& payload,
    uint64_t created_at,
    const std::vector<NostrTag>& tags,
    const std::array<uint8_t, 32>& signing_secret);
SignedNostrEvent sign_encrypted_anchor_event(
    const AnchorEventPayload& payload,
    uint64_t created_at,
    const std::vector<NostrTag>& tags,
    const std::array<uint8_t, 32>& signing_secret);
AnchorEventPayload verify_decrypt_anchor_event(
    const SignedNostrEvent& event,
    const SchnorrPublicKey& trusted_public_key,
    const std::array<uint8_t, 32>& decryption_secret);
