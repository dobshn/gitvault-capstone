#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto/schnorr.h"

using NostrTag = std::vector<std::string>;

struct UnsignedNostrEvent {
  uint64_t created_at = 0;
  uint16_t kind = 0;
  std::vector<NostrTag> tags;
  std::string content;
};

struct SignedNostrEvent {
  std::array<uint8_t, 32> id{};
  SchnorrPublicKey public_key{};
  uint64_t created_at = 0;
  uint16_t kind = 0;
  std::vector<NostrTag> tags;
  std::string content;
  SchnorrSignature signature{};
};

std::string serialize_nostr_event_canonical(
    const SchnorrPublicKey& public_key,
    const UnsignedNostrEvent& event);
std::array<uint8_t, 32> compute_nostr_event_id(
    const SchnorrPublicKey& public_key,
    const UnsignedNostrEvent& event);

SignedNostrEvent sign_nostr_event(
    const UnsignedNostrEvent& event,
    const std::array<uint8_t, 32>& signing_secret);
bool verify_nostr_event(const SignedNostrEvent& event,
                        const SchnorrPublicKey& trusted_public_key);

std::string serialize_nostr_event_json(const SignedNostrEvent& event);
SignedNostrEvent deserialize_nostr_event_json(const std::string& json_text);
