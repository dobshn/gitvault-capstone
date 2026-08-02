#include "nostr_event.h"

#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

#include "crypto/sha256.h"
#include "json.hpp"
#include "util.h"

namespace {
using nlohmann::json;

void validate_tags(const std::vector<NostrTag>& tags) {
  for (const auto& tag : tags) {
    if (tag.empty()) {
      throw std::runtime_error("Nostr tags must contain at least one string");
    }
  }
}

json make_tags_json(const std::vector<NostrTag>& tags) {
  validate_tags(tags);
  json result = json::array();
  for (const auto& tag : tags) {
    result.push_back(tag);
  }
  return result;
}

std::string dump_strict(const json& value) {
  try {
    return value.dump(-1, ' ', false, json::error_handler_t::strict);
  } catch (const std::exception& error) {
    throw std::runtime_error(std::string("failed to serialize Nostr JSON: ") +
                             error.what());
  }
}

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

std::vector<NostrTag> parse_tags(const json& value) {
  if (!value.is_array()) {
    throw std::runtime_error("tags must be an array");
  }

  std::vector<NostrTag> tags;
  tags.reserve(value.size());
  for (const auto& encoded_tag : value) {
    if (!encoded_tag.is_array() || encoded_tag.empty()) {
      throw std::runtime_error("each Nostr tag must be a non-empty array");
    }
    NostrTag tag;
    tag.reserve(encoded_tag.size());
    for (const auto& element : encoded_tag) {
      if (!element.is_string()) {
        throw std::runtime_error("Nostr tag elements must be strings");
      }
      tag.push_back(element.get<std::string>());
    }
    tags.push_back(std::move(tag));
  }
  return tags;
}

UnsignedNostrEvent unsigned_part(const SignedNostrEvent& event) {
  return UnsignedNostrEvent{
      event.created_at, event.kind, event.tags, event.content};
}
}  // namespace

std::string serialize_nostr_event_canonical(
    const SchnorrPublicKey& public_key,
    const UnsignedNostrEvent& event) {
  json canonical = json::array();
  canonical.push_back(0);
  canonical.push_back(array_to_hex(public_key));
  canonical.push_back(event.created_at);
  canonical.push_back(event.kind);
  canonical.push_back(make_tags_json(event.tags));
  canonical.push_back(event.content);
  return dump_strict(canonical);
}

std::array<uint8_t, 32> compute_nostr_event_id(
    const SchnorrPublicKey& public_key,
    const UnsignedNostrEvent& event) {
  const std::string canonical =
      serialize_nostr_event_canonical(public_key, event);
  return Sha256::hash(ByteVec(canonical.begin(), canonical.end()));
}

SignedNostrEvent sign_nostr_event(
    const UnsignedNostrEvent& event,
    const std::array<uint8_t, 32>& signing_secret) {
  SignedNostrEvent signed_event;
  signed_event.public_key = schnorr_public_key(signing_secret);
  signed_event.created_at = event.created_at;
  signed_event.kind = event.kind;
  signed_event.tags = event.tags;
  signed_event.content = event.content;
  signed_event.id = compute_nostr_event_id(signed_event.public_key, event);

  const ByteVec random = random_bytes(32);
  std::array<uint8_t, 32> auxiliary_randomness{};
  std::copy(random.begin(), random.end(), auxiliary_randomness.begin());
  signed_event.signature = schnorr_sign_digest(
      signing_secret, signed_event.id, auxiliary_randomness);
  return signed_event;
}

bool verify_nostr_event(const SignedNostrEvent& event,
                        const SchnorrPublicKey& trusted_public_key) {
  try {
    const auto expected_id =
        compute_nostr_event_id(event.public_key, unsigned_part(event));
    return constant_time_equal(event.public_key, trusted_public_key) &&
           constant_time_equal(expected_id, event.id) &&
           schnorr_verify_digest(event.public_key, event.id, event.signature);
  } catch (const std::exception&) {
    return false;
  }
}

std::string serialize_nostr_event_json(const SignedNostrEvent& event) {
  validate_tags(event.tags);
  json encoded = {
      {"id", array_to_hex(event.id)},
      {"pubkey", array_to_hex(event.public_key)},
      {"created_at", event.created_at},
      {"kind", event.kind},
      {"tags", make_tags_json(event.tags)},
      {"content", event.content},
      {"sig", array_to_hex(event.signature)},
  };
  return dump_strict(encoded);
}

SignedNostrEvent deserialize_nostr_event_json(const std::string& json_text) {
  try {
    std::set<std::string> parsed_keys;
    bool duplicate_key = false;
    const json::parser_callback_t reject_duplicate_keys =
        [&](int, json::parse_event_t parse_event, json& parsed) {
          if (parse_event == json::parse_event_t::key &&
              !parsed_keys.insert(parsed.get<std::string>()).second) {
            duplicate_key = true;
          }
          return true;
        };
    const json encoded = json::parse(json_text, reject_duplicate_keys);
    if (duplicate_key) {
      throw std::runtime_error("duplicate event fields are not allowed");
    }
    if (!encoded.is_object() || encoded.size() != 7 ||
        !encoded.contains("id") || !encoded.contains("pubkey") ||
        !encoded.contains("created_at") || !encoded.contains("kind") ||
        !encoded.contains("tags") || !encoded.contains("content") ||
        !encoded.contains("sig")) {
      throw std::runtime_error(
          "event must contain exactly the seven NIP-01 fields");
    }

    SignedNostrEvent event;
    event.id = parse_fixed_lower_hex<32>(encoded.at("id"), "id");
    event.public_key =
        parse_fixed_lower_hex<32>(encoded.at("pubkey"), "pubkey");
    event.created_at = parse_unsigned_integer(encoded.at("created_at"),
                                               "created_at");
    const uint64_t kind = parse_unsigned_integer(encoded.at("kind"), "kind");
    if (kind > std::numeric_limits<uint16_t>::max()) {
      throw std::runtime_error("kind must be between 0 and 65535");
    }
    event.kind = static_cast<uint16_t>(kind);
    event.tags = parse_tags(encoded.at("tags"));
    if (!encoded.at("content").is_string()) {
      throw std::runtime_error("content must be a string");
    }
    event.content = encoded.at("content").get<std::string>();
    event.signature = parse_fixed_lower_hex<64>(encoded.at("sig"), "sig");
    return event;
  } catch (const std::exception& error) {
    throw std::runtime_error(std::string("invalid Nostr event JSON: ") +
                             error.what());
  }
}
