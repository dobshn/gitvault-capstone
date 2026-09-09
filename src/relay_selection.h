#pragma once

#include <functional>
#include <string>
#include <vector>

#include "anchor_channel.h"

const std::vector<std::string>& default_relay_candidates();

// A successful probe measures read availability, not retention or write access.
using RelayProbe = std::function<AnchorFetchEndpointResult(const std::string&)>;
std::vector<std::string> select_init_relays(
    const std::vector<std::string>& candidates,
    const RelayProbe& probe);
std::vector<std::string> discover_init_relays();
