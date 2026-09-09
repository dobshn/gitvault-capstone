#include "relay_selection.h"

#include <algorithm>
#include <future>
#include <set>
#include <stdexcept>

#include "nostr_anchor_channel.h"
#include "util.h"

const std::vector<std::string>& default_relay_candidates() {
  // Bootstrap hints only: availability is measured on every init.
  static const std::vector<std::string> candidates = {
      "wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.com",
      "wss://relay.primal.net", "wss://relay.ditto.pub"};
  return candidates;
}

std::vector<std::string> select_init_relays(
    const std::vector<std::string>& candidates, const RelayProbe& probe) {
  std::set<std::string> unique(candidates.begin(), candidates.end());
  std::vector<std::future<AnchorFetchEndpointResult>> pending;
  for (const auto& endpoint : unique) {
    pending.push_back(std::async(std::launch::async, [&, endpoint] {
      try {
        auto result = probe(endpoint);
        result.endpoint = endpoint;
        return result;
      } catch (const std::exception& error) {
        return AnchorFetchEndpointResult{
            endpoint, AnchorFetchStatus::TransportError, error.what(), 0};
      }
    }));
  }
  std::vector<AnchorFetchEndpointResult> available;
  std::string diagnostics;
  for (auto& operation : pending) {
    auto result = operation.get();
    if (result.status == AnchorFetchStatus::Synchronized) {
      available.push_back(result);
    } else {
      diagnostics += "\n  " + result.endpoint + ": " + result.message;
    }
  }
  if (available.size() < 3) {
    throw std::runtime_error(
        "automatic relay selection found only " +
        std::to_string(available.size()) +
        " responsive relays; three are required. Retry or provide exactly "
        "three --relay wss://... options." + diagnostics);
  }
  std::sort(available.begin(), available.end(), [](const auto& a, const auto& b) {
    if (a.latency_milliseconds != b.latency_milliseconds)
      return a.latency_milliseconds < b.latency_milliseconds;
    return a.endpoint < b.endpoint;
  });
  return {available[0].endpoint, available[1].endpoint, available[2].endpoint};
}

std::vector<std::string> discover_init_relays() {
  // Use a disposable identity and random filter, never the Vault identity.
  std::array<uint8_t, 32> secret{};
  const auto bytes = random_bytes(secret.size());
  std::copy(bytes.begin(), bytes.end(), secret.begin());
  const auto author = schnorr_public_key(secret);
  const auto tag = to_hex(random_bytes(32));
  return select_init_relays(default_relay_candidates(), [&](const auto& endpoint) {
    NostrAnchorChannel channel({endpoint}, secret);
    AnchorFetchEndpointResult combined{
        endpoint, AnchorFetchStatus::Synchronized, "", 0};
    for (const uint16_t kind : {uint16_t(9500), uint16_t(30078)}) {
      AnchorChannelQuery query;
      query.author = author;
      query.kind = kind;
      query.required_tags = {{"t", tag}};
      if (kind == 30078) query.required_tags.push_back({"d", "gitvault:" + tag});
      auto result = channel.fetch(query).endpoints.at(0);
      if (result.status != AnchorFetchStatus::Synchronized) return result;
      combined.latency_milliseconds += result.latency_milliseconds;
    }
    return combined;
  });
}
