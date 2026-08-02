#include "client_bootstrap.h"

#include <algorithm>
#include <fstream>
#include <set>
#include <stdexcept>

#include "json.hpp"

namespace {
using nlohmann::json;
constexpr size_t kMaximumBootstrapBytes = 64 * 1024 * 1024;
constexpr size_t kMaximumBootstrapEvents = 4096;

void require_fields(const json& value,
                    const std::set<std::string>& expected) {
  if (!value.is_object() || value.size() != expected.size()) {
    throw std::runtime_error("bootstrap fields do not match");
  }
  for (const auto& field : expected) {
    if (!value.contains(field)) {
      throw std::runtime_error("bootstrap missing field: " + field);
    }
  }
}

void protect_bootstrap_file(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace, error);
  if (error) {
    throw std::runtime_error("failed to protect bootstrap file: " +
                             error.message());
  }
}
}  // namespace

void write_client_bootstrap(const std::filesystem::path& path,
                            const ClientBootstrap& bootstrap) {
  if (path.empty() || bootstrap.vault_name.empty() ||
      bootstrap.events.size() > kMaximumBootstrapEvents) {
    throw std::runtime_error("invalid client bootstrap");
  }
  json events = json::array();
  for (const auto& event : bootstrap.events) {
    events.push_back(json::parse(serialize_nostr_event_json(event)));
  }
  const json value = {
      {"channel", json::parse(serialize_anchor_channel_config(
                      bootstrap.channel))},
      {"checkpoint", json::parse(serialize_anchor_checkpoint(
                         bootstrap.checkpoint))},
      {"config", to_hex(bootstrap.config_bytes)},
      {"events", events},
      {"format_version", bootstrap.format_version},
      {"vault_name", bootstrap.vault_name},
      {"wrapped_identity", to_hex(bootstrap.wrapped_identity)},
  };
  const std::string encoded = value.dump();
  if (encoded.size() > kMaximumBootstrapBytes) {
    throw std::runtime_error("client bootstrap exceeds size limit");
  }
  if (std::filesystem::exists(path)) {
    throw std::runtime_error("bootstrap output already exists: " +
                             path.string());
  }
  std::filesystem::path temporary = path;
  temporary += ".tmp-" + to_hex(random_bytes(8));
  try {
    write_file_bytes(temporary, ByteVec(encoded.begin(), encoded.end()));
    protect_bootstrap_file(temporary);
    std::filesystem::rename(temporary, path);
  } catch (...) {
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    throw;
  }
}

ClientBootstrap read_client_bootstrap(const std::filesystem::path& path) {
  const ByteVec bytes = read_file_bytes(path);
  if (bytes.empty() || bytes.size() > kMaximumBootstrapBytes) {
    throw std::runtime_error("invalid bootstrap file size");
  }
  const std::string encoded(bytes.begin(), bytes.end());
  const json value = json::parse(encoded);
  if (value.dump() != encoded) {
    throw std::runtime_error("bootstrap JSON is not canonical");
  }
  require_fields(value,
                 {"channel", "checkpoint", "config", "events",
                  "format_version", "vault_name", "wrapped_identity"});
  ClientBootstrap result;
  result.format_version = value.at("format_version").get<uint8_t>();
  result.vault_name = value.at("vault_name").get<std::string>();
  result.config_bytes = from_hex(value.at("config").get<std::string>());
  result.wrapped_identity =
      from_hex(value.at("wrapped_identity").get<std::string>());
  result.channel = deserialize_anchor_channel_config(
      value.at("channel").dump());
  result.checkpoint = deserialize_anchor_checkpoint(
      value.at("checkpoint").dump());
  if (!value.at("events").is_array() ||
      value.at("events").size() > kMaximumBootstrapEvents) {
    throw std::runtime_error("invalid bootstrap event list");
  }
  std::set<AnchorHash> ids;
  for (const auto& item : value.at("events")) {
    SignedNostrEvent event = deserialize_nostr_event_json(item.dump());
    if (!ids.insert(event.id).second) {
      throw std::runtime_error("duplicate bootstrap event ID");
    }
    result.events.push_back(std::move(event));
  }
  if (result.format_version != 1 || result.vault_name.empty() ||
      result.vault_name.find('/') != std::string::npos ||
      result.vault_name.find('\\') != std::string::npos ||
      result.config_bytes.empty() || result.wrapped_identity.empty() ||
      ids.count(result.channel.genesis_event_id) == 0) {
    throw std::runtime_error("unsupported or invalid client bootstrap");
  }
  return result;
}
