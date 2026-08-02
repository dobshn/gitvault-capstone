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
};

struct AnchorPublishReceipt {
  std::string endpoint;
  std::array<uint8_t, 32> event_id{};
  AnchorPublishStatus status = AnchorPublishStatus::Accepted;
};

class IAnchorChannel {
public:
  virtual ~IAnchorChannel() = default;

  // A receipt means only that the transport accepted the event. It does not
  // make the event trusted or advance the Vault state.
  virtual std::vector<AnchorPublishReceipt> publish(
      const SignedNostrEvent& event) = 0;
  // Returned events are untrusted. The caller must verify their Vault key,
  // canonical ID, signature, and protocol semantics before using them.
  virtual std::vector<SignedNostrEvent> fetch(
      const AnchorChannelQuery& query = {}) const = 0;
};
