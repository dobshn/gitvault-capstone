#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "nostr_event.h"

struct AnchorChannelQuery {
  std::optional<SchnorrPublicKey> author;
  std::optional<uint16_t> kind;
  // Every tag listed here must exactly match one tag in the event.
  std::vector<NostrTag> required_tags;
};

enum class AnchorPublishStatus {
  Accepted,
  AlreadyPresent,
  Rejected,
  Timeout,
  TransportError,
};

struct AnchorPublishReceipt {
  std::string endpoint;
  std::array<uint8_t, 32> event_id{};
  AnchorPublishStatus status = AnchorPublishStatus::Accepted;
  std::string message;
  uint64_t latency_milliseconds = 0;
};

struct AnchorPublishResult {
  std::vector<AnchorPublishReceipt> endpoints;

  size_t accepted_count() const;
};

enum class AnchorFetchStatus {
  Synchronized,
  Rejected,
  Timeout,
  TransportError,
};

struct AnchorFetchEndpointResult {
  std::string endpoint;
  AnchorFetchStatus status = AnchorFetchStatus::TransportError;
  std::string message;
  uint64_t latency_milliseconds = 0;
};

struct AnchorFetchResult {
  std::vector<SignedNostrEvent> events;
  std::vector<AnchorFetchEndpointResult> endpoints;

  size_t synchronized_count() const;
};

class IAnchorChannel {
public:
  virtual ~IAnchorChannel() = default;

  // A receipt means only that the transport accepted the event. It does not
  // make the event trusted or advance the Vault state.
  virtual AnchorPublishResult publish(
      const SignedNostrEvent& event) = 0;
  // Returned events are untrusted. The caller must verify their Vault key,
  // canonical ID, signature, and protocol semantics before using them.
  virtual AnchorFetchResult fetch(
      const AnchorChannelQuery& query = {}) const = 0;
};
