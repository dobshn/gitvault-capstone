#pragma once

#include <array>
#include <chrono>
#include <string>
#include <vector>

#include "anchor_channel.h"

struct NostrAnchorChannelOptions {
  std::chrono::seconds connect_timeout{5};
  std::chrono::seconds operation_timeout{10};
  size_t maximum_events = 4096;
  size_t maximum_frame_bytes = 64 * 1024;
  size_t maximum_content_bytes = 16 * 1024;
};

class NostrAnchorChannel final : public IAnchorChannel {
public:
  NostrAnchorChannel(
      std::vector<std::string> relay_urls,
      std::array<uint8_t, 32> signing_secret,
      NostrAnchorChannelOptions options = {});

  AnchorPublishResult publish(const SignedNostrEvent& event) override;
  AnchorFetchResult fetch(const AnchorChannelQuery& query = {}) const override;

  const std::vector<std::string>& relay_urls() const;

private:
  std::vector<std::string> relay_urls_;
  std::array<uint8_t, 32> signing_secret_{};
  NostrAnchorChannelOptions options_;
};
