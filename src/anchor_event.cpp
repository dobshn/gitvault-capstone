#include "anchor_event.h"

#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>
#include <type_traits>

#include "json.hpp"
#include "util.h"

namespace {
using nlohmann::json;

template <size_t N>
std::string array_to_hex(const std::array<uint8_t, N>& value) {
  return to_hex(ByteVec(value.begin(), value.end()));
}

bool is_lower_hex(const std::string& value) {
  return std::all_of(value.begin(), value.end(), [](char character) {
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f');
  });
}

template <size_t N>
std::array<uint8_t, N> parse_fixed_lower_hex(const json& value,
                                              const char* field_name) {
  if (!value.is_string()) {
    throw std::runtime_error(std::string(field_name) + " must be a string");
  }
  const std::string encoded = value.get<std::string>();
  if (encoded.size() != N * 2 || !is_lower_hex(encoded)) {
    throw std::runtime_error(std::string(field_name) +
                             " must be fixed-length lowercase hex");
  }
  const ByteVec decoded = from_hex(encoded);
  std::array<uint8_t, N> result{};
  std::copy(decoded.begin(), decoded.end(), result.begin());
  return result;
}

uint64_t parse_unsigned_integer(const json& value, const char* field_name) {
  if (!value.is_number_unsigned()) {
    throw std::runtime_error(std::string(field_name) +
                             " must be a non-negative integer");
  }
  return value.get<uint64_t>();
}

uint8_t parse_u8(const json& value, const char* field_name) {
  const uint64_t parsed = parse_unsigned_integer(value, field_name);
  if (parsed > std::numeric_limits<uint8_t>::max()) {
    throw std::runtime_error(std::string(field_name) + " is out of range");
  }
  return static_cast<uint8_t>(parsed);
}

std::string parse_string(const json& value, const char* field_name) {
  if (!value.is_string()) {
    throw std::runtime_error(std::string(field_name) + " must be a string");
  }
  return value.get<std::string>();
}

json parse_without_duplicate_keys(const std::string& encoded) {
  std::set<std::string> parsed_keys;
  bool duplicate_key = false;
  const json::parser_callback_t reject_duplicate_keys =
      [&](int, json::parse_event_t event, json& parsed) {
        if (event == json::parse_event_t::key &&
            !parsed_keys.insert(parsed.get<std::string>()).second) {
          duplicate_key = true;
        }
        return true;
      };
  json value = json::parse(encoded, reject_duplicate_keys);
  if (duplicate_key) {
    throw std::runtime_error("duplicate anchor payload fields are not allowed");
  }
  return value;
}

void require_exact_fields(const json& value,
                          const std::set<std::string>& expected_fields) {
  if (!value.is_object() || value.size() != expected_fields.size()) {
    throw std::runtime_error("anchor payload fields do not match its event type");
  }
  for (const auto& field : expected_fields) {
    if (!value.contains(field)) {
      throw std::runtime_error("anchor payload is missing field: " + field);
    }
  }
}

AnchorEventCommon parse_common(const json& value) {
  AnchorEventCommon common;
  common.protocol_version = parse_u8(value.at("protocol_version"),
                                     "protocol_version");
  if (common.protocol_version != kAnchorProtocolVersion) {
    throw std::runtime_error("unsupported anchor protocol version");
  }
  common.vault_id = parse_fixed_lower_hex<32>(value.at("vault_id"),
                                               "vault_id");
  common.operation_id = parse_fixed_lower_hex<16>(value.at("operation_id"),
                                                   "operation_id");
  common.protocol_epoch = parse_unsigned_integer(value.at("protocol_epoch"),
                                                  "protocol_epoch");
  common.installation_id = parse_string(value.at("installation_id"),
                                         "installation_id");
  return common;
}

json common_json(const AnchorEventCommon& common, const char* event_type) {
  if (common.protocol_version != kAnchorProtocolVersion) {
    throw std::runtime_error("unsupported anchor protocol version");
  }
  return {
      {"protocol_version", common.protocol_version},
      {"event_type", event_type},
      {"vault_id", array_to_hex(common.vault_id)},
      {"operation_id", array_to_hex(common.operation_id)},
      {"protocol_epoch", common.protocol_epoch},
      {"installation_id", common.installation_id},
  };
}

std::string dump_strict(const json& value) {
  try {
    return value.dump(-1, ' ', false, json::error_handler_t::strict);
  } catch (const std::exception& error) {
    throw std::runtime_error(
        std::string("failed to serialize anchor payload: ") + error.what());
  }
}
}  // namespace

const AnchorEventCommon& anchor_event_common(
    const AnchorEventPayload& payload) {
  return std::visit(
      [](const auto& event) -> const AnchorEventCommon& {
        return event.common;
      },
      payload);
}

std::string serialize_anchor_event_payload(
    const AnchorEventPayload& payload) {
  const json encoded = std::visit(
      [](const auto& event) {
        using Event = std::decay_t<decltype(event)>;
        if constexpr (std::is_same_v<Event, VaultGenesisEvent>) {
          json value = common_json(event.common, "vault_genesis");
          value["config_hash"] = array_to_hex(event.config_hash);
          value["initial_head"] = array_to_hex(event.initial_head);
          return value;
        } else if constexpr (std::is_same_v<Event, HeadProposalEvent>) {
          if (event.commit_format_version != kAnchorCommitFormatVersion) {
            throw std::runtime_error("unsupported proposal commit format");
          }
          json value = common_json(event.common, "head_proposal");
          value["previous_head"] = array_to_hex(event.previous_head);
          value["new_head"] = array_to_hex(event.new_head);
          value["parent_event_id"] = array_to_hex(event.parent_event_id);
          value["commit_format_version"] = event.commit_format_version;
          return value;
        } else {
          json value = common_json(event.common, "head_observation");
          value["proposal_event_id"] = array_to_hex(event.proposal_event_id);
          value["expected_previous_head"] =
              array_to_hex(event.expected_previous_head);
          value["observed_cloud_head"] =
              array_to_hex(event.observed_cloud_head);
          value["observed_cloud_revision"] =
              event.observed_cloud_revision;
          return value;
        }
      },
      payload);
  return dump_strict(encoded);
}

AnchorEventPayload deserialize_anchor_event_payload(
    const std::string& canonical_json) {
  try {
    const json encoded = parse_without_duplicate_keys(canonical_json);
    if (!encoded.is_object() || !encoded.contains("event_type")) {
      throw std::runtime_error("anchor payload must contain event_type");
    }
    const std::string event_type =
        parse_string(encoded.at("event_type"), "event_type");

    AnchorEventPayload payload;
    if (event_type == "vault_genesis") {
      require_exact_fields(encoded, {
          "protocol_version", "event_type", "vault_id", "operation_id",
          "protocol_epoch", "installation_id", "config_hash", "initial_head",
      });
      VaultGenesisEvent event;
      event.common = parse_common(encoded);
      event.config_hash = parse_fixed_lower_hex<32>(encoded.at("config_hash"),
                                                     "config_hash");
      event.initial_head = parse_fixed_lower_hex<32>(encoded.at("initial_head"),
                                                      "initial_head");
      payload = event;
    } else if (event_type == "head_proposal") {
      require_exact_fields(encoded, {
          "protocol_version", "event_type", "vault_id", "operation_id",
          "protocol_epoch", "installation_id", "previous_head", "new_head",
          "parent_event_id", "commit_format_version",
      });
      HeadProposalEvent event;
      event.common = parse_common(encoded);
      event.previous_head = parse_fixed_lower_hex<32>(
          encoded.at("previous_head"), "previous_head");
      event.new_head = parse_fixed_lower_hex<32>(encoded.at("new_head"),
                                                  "new_head");
      event.parent_event_id = parse_fixed_lower_hex<32>(
          encoded.at("parent_event_id"), "parent_event_id");
      event.commit_format_version = parse_u8(
          encoded.at("commit_format_version"), "commit_format_version");
      if (event.commit_format_version != kAnchorCommitFormatVersion) {
        throw std::runtime_error("unsupported proposal commit format");
      }
      payload = event;
    } else if (event_type == "head_observation") {
      require_exact_fields(encoded, {
          "protocol_version", "event_type", "vault_id", "operation_id",
          "protocol_epoch", "installation_id", "proposal_event_id",
          "expected_previous_head", "observed_cloud_head",
          "observed_cloud_revision",
      });
      HeadObservationEvent event;
      event.common = parse_common(encoded);
      event.proposal_event_id = parse_fixed_lower_hex<32>(
          encoded.at("proposal_event_id"), "proposal_event_id");
      event.expected_previous_head = parse_fixed_lower_hex<32>(
          encoded.at("expected_previous_head"), "expected_previous_head");
      event.observed_cloud_head = parse_fixed_lower_hex<32>(
          encoded.at("observed_cloud_head"), "observed_cloud_head");
      event.observed_cloud_revision = parse_string(
          encoded.at("observed_cloud_revision"), "observed_cloud_revision");
      payload = event;
    } else {
      throw std::runtime_error("unsupported anchor event type");
    }

    if (serialize_anchor_event_payload(payload) != canonical_json) {
      throw std::runtime_error("anchor payload is not canonical JSON");
    }
    return payload;
  } catch (const std::exception& error) {
    throw std::runtime_error(std::string("invalid anchor event payload: ") +
                             error.what());
  }
}

SignedNostrEvent sign_anchor_event(
    const AnchorEventPayload& payload,
    uint64_t created_at,
    const std::vector<NostrTag>& tags,
    const std::array<uint8_t, 32>& signing_secret) {
  UnsignedNostrEvent event;
  event.created_at = created_at;
  event.kind = kGitVaultAnchorEventKind;
  event.tags = tags;
  event.content = serialize_anchor_event_payload(payload);
  return sign_nostr_event(event, signing_secret);
}
