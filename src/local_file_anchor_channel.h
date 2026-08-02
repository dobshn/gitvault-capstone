#pragma once

#include <filesystem>

#include "anchor_channel.h"

class LocalFileAnchorChannel final : public IAnchorChannel {
public:
  explicit LocalFileAnchorChannel(std::filesystem::path root_directory);

  std::vector<AnchorPublishReceipt> publish(
      const SignedNostrEvent& event) override;
  std::vector<SignedNostrEvent> fetch(
      const AnchorChannelQuery& query = {}) const override;

  const std::filesystem::path& root_directory() const;

private:
  std::filesystem::path event_directory() const;
  void ensure_event_directory() const;

  std::filesystem::path root_directory_;
};
