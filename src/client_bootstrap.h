#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "anchor_trust_store.h"
#include "util.h"

struct ClientBootstrap {
  uint8_t format_version = 2;
  std::string vault_name;
  ByteVec config_bytes;
  ByteVec wrapped_identity;
  AnchorChannelConfig channel;
  AnchorCheckpoint checkpoint;
  std::vector<SignedNostrEvent> events;
};

void write_client_bootstrap(const std::filesystem::path& path,
                            const ClientBootstrap& bootstrap);
ClientBootstrap read_client_bootstrap(const std::filesystem::path& path);
