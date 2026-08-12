#include "anchor_trust_store.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <stdexcept>
#include <system_error>

#include "crypto/hmac.h"
#include "json.hpp"

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {
using nlohmann::json;

constexpr size_t kMaxTrustFileBytes = 1024 * 1024;

template <size_t N>
std::string fixed_hex(const std::array<uint8_t, N>& value) {
  return to_hex(ByteVec(value.begin(), value.end()));
}

template <size_t N>
std::array<uint8_t, N> fixed_from_hex(const json& value,
                                      const char* field) {
  if (!value.is_string()) {
    throw std::runtime_error(std::string(field) + " must be a string");
  }
  const std::string encoded = value.get<std::string>();
  const ByteVec decoded = from_hex(encoded);
  if (decoded.size() != N ||
      !std::all_of(encoded.begin(), encoded.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
      })) {
    throw std::runtime_error(std::string(field) +
                             " must be fixed-length lowercase hex");
  }
  std::array<uint8_t, N> result{};
  std::copy(decoded.begin(), decoded.end(), result.begin());
  return result;
}

json clock_json(const VectorClock& clock) {
  validate_vector_clock(clock);
  json result = json::array();
  for (const auto& [replica_id, counter] : clock) {
    result.push_back(json::array({fixed_hex(replica_id), counter}));
  }
  return result;
}

VectorClock parse_clock(const json& value, const char* field) {
  if (!value.is_array() || value.size() > kMaximumVectorClockEntries) {
    throw std::runtime_error(std::string(field) + " must be a bounded array");
  }
  VectorClock result;
  ReplicaId previous{};
  bool have_previous = false;
  for (const auto& item : value) {
    if (!item.is_array() || item.size() != 2 ||
        !item.at(1).is_number_unsigned()) {
      throw std::runtime_error(std::string(field) +
                               " component must be [replica,counter]");
    }
    const ReplicaId replica = fixed_from_hex<16>(item.at(0), field);
    const uint64_t counter = item.at(1).get<uint64_t>();
    if (counter == 0 || (have_previous && !(previous < replica)) ||
        !result.emplace(replica, counter).second) {
      throw std::runtime_error(std::string(field) +
                               " must be non-zero, unique, and sorted");
    }
    previous = replica;
    have_previous = true;
  }
  validate_vector_clock(result);
  return result;
}

void require_exact_fields(const json& value,
                          const std::set<std::string>& fields,
                          const char* type) {
  if (!value.is_object() || value.size() != fields.size()) {
    throw std::runtime_error(std::string(type) + " fields do not match");
  }
  for (const auto& field : fields) {
    if (!value.contains(field)) {
      throw std::runtime_error(std::string(type) + " missing field: " + field);
    }
  }
}

void protect_directory(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error) {
    throw std::runtime_error("failed to create trust directory: " +
                             error.message());
  }
  std::filesystem::permissions(path, std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace, error);
  if (error) {
    throw std::runtime_error("failed to protect trust directory: " +
                             error.message());
  }
}

void sync_directory(const std::filesystem::path& path) {
#if !defined(_WIN32)
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    throw std::runtime_error("failed to open directory for fsync: " +
                             path.string());
  }
  const int result = ::fsync(fd);
  const int saved_errno = errno;
  ::close(fd);
  if (result != 0) {
    throw std::runtime_error("failed to fsync directory: " +
                             std::string(std::strerror(saved_errno)));
  }
#else
  (void)path;
#endif
}

void write_secure_atomic(const std::filesystem::path& path,
                         const std::string& content) {
  protect_directory(path.parent_path());
  std::filesystem::path temporary = path;
  temporary += ".tmp-" + to_hex(random_bytes(8));
#if !defined(_WIN32)
  const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    throw std::runtime_error("failed to create temporary trust file: " +
                             temporary.string());
  }
  bool open = true;
  try {
    size_t offset = 0;
    while (offset < content.size()) {
      const ssize_t written =
          ::write(fd, content.data() + offset, content.size() - offset);
      if (written <= 0) {
        throw std::runtime_error("failed to write temporary trust file");
      }
      offset += static_cast<size_t>(written);
    }
    if (::fsync(fd) != 0) {
      throw std::runtime_error("failed to fsync temporary trust file");
    }
    ::close(fd);
    open = false;
    std::filesystem::rename(temporary, path);
    sync_directory(path.parent_path());
  } catch (...) {
    if (open) ::close(fd);
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    throw;
  }
#else
  write_file_bytes(temporary, ByteVec(content.begin(), content.end()));
  std::error_code error;
  std::filesystem::permissions(
      temporary,
      std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace, error);
  if (error) {
    throw std::runtime_error("failed to protect temporary trust file");
  }
  std::filesystem::rename(temporary, path);
#endif
}

std::string read_small_text(const std::filesystem::path& path) {
  const ByteVec bytes = read_file_bytes(path);
  if (bytes.size() > kMaxTrustFileBytes) {
    throw std::runtime_error("trust metadata file is too large: " +
                             path.string());
  }
  return std::string(bytes.begin(), bytes.end());
}

ByteVec metadata_mac_input(const char* type, const std::string& payload) {
  const std::string prefix =
      std::string("gitvault/trust-metadata/v1/") + type;
  ByteVec input(prefix.begin(), prefix.end());
  input.push_back(0);
  input.insert(input.end(), payload.begin(), payload.end());
  return input;
}

void write_authenticated(const std::filesystem::path& path,
                         const char* type,
                         const json& payload,
                         const ByteVec& key) {
  const std::string canonical = payload.dump();
  const auto mac = hmac_sha256(key, metadata_mac_input(type, canonical));
  const json envelope = {
      {"mac", fixed_hex(mac)},
      {"payload", payload},
      {"type", type},
      {"version", 1},
  };
  write_secure_atomic(path, envelope.dump());
}

json read_authenticated(const std::filesystem::path& path,
                        const char* expected_type,
                        const ByteVec& key) {
  const json envelope = json::parse(read_small_text(path));
  require_exact_fields(envelope, {"mac", "payload", "type", "version"},
                       "trust envelope");
  if (envelope.at("version") != 1 || envelope.at("type") != expected_type) {
    throw std::runtime_error("unsupported trust metadata envelope");
  }
  const std::string canonical = envelope.at("payload").dump();
  const auto expected =
      hmac_sha256(key, metadata_mac_input(expected_type, canonical));
  const auto actual = fixed_from_hex<32>(envelope.at("mac"), "mac");
  if (!constant_time_equal(expected, actual)) {
    throw std::runtime_error("trust metadata authentication failed");
  }
  return envelope.at("payload");
}

json channel_json(const AnchorChannelConfig& value) {
  return {
      {"channel_id", fixed_hex(value.channel_id)},
      {"config_hash", fixed_hex(value.config_hash)},
      {"format_version", value.format_version},
      {"genesis_event_id", fixed_hex(value.genesis_event_id)},
      {"installation_id", value.installation_id},
      {"protocol_epoch", value.protocol_epoch},
      {"protocol_version", value.protocol_version},
      {"publish_quorum", value.publish_quorum},
      {"read_quorum", value.read_quorum},
      {"relay_urls", value.relay_urls},
      {"vault_id", fixed_hex(value.vault_id)},
      {"vault_public_key", fixed_hex(value.vault_public_key)},
  };
}

AnchorChannelConfig parse_channel(const json& value) {
  require_exact_fields(
      value,
      {"channel_id", "config_hash", "format_version", "genesis_event_id",
       "installation_id", "protocol_epoch", "protocol_version",
       "publish_quorum", "read_quorum", "relay_urls", "vault_id",
       "vault_public_key"},
      "channel config");
  AnchorChannelConfig result;
  result.format_version = value.at("format_version").get<uint8_t>();
  result.protocol_version = value.at("protocol_version").get<uint8_t>();
  result.protocol_epoch = value.at("protocol_epoch").get<uint64_t>();
  result.vault_id = fixed_from_hex<32>(value.at("vault_id"), "vault_id");
  result.channel_id =
      fixed_from_hex<32>(value.at("channel_id"), "channel_id");
  result.vault_public_key =
      fixed_from_hex<32>(value.at("vault_public_key"), "vault_public_key");
  result.genesis_event_id = fixed_from_hex<32>(
      value.at("genesis_event_id"), "genesis_event_id");
  result.config_hash =
      fixed_from_hex<32>(value.at("config_hash"), "config_hash");
  result.installation_id = value.at("installation_id").get<std::string>();
  result.relay_urls = value.at("relay_urls").get<std::vector<std::string>>();
  result.publish_quorum = value.at("publish_quorum").get<uint8_t>();
  result.read_quorum = value.at("read_quorum").get<uint8_t>();
  if (result.format_version != 2 ||
      result.protocol_version != kAnchorProtocolVersion ||
      result.relay_urls.size() != 3 || result.publish_quorum != 2 ||
      std::set<std::string>(result.relay_urls.begin(),
                            result.relay_urls.end()).size() != 3 ||
      (result.read_quorum != 2 && result.read_quorum != 3) ||
      result.installation_id.size() != 32 ||
      from_hex(result.installation_id).size() != 16) {
    throw std::runtime_error("unsupported or invalid channel policy");
  }
  return result;
}

json checkpoint_json(const AnchorCheckpoint& value) {
  return {{"accepted_head", fixed_hex(value.accepted_head)},
          {"accepted_clock", clock_json(value.accepted_clock)},
          {"cloud_revision", value.cloud_revision},
          {"format_version", value.format_version},
          {"head_envelope_hash", fixed_hex(value.head_envelope_hash)},
          {"last_checkpoint_created_at", value.last_checkpoint_created_at},
          {"protocol_epoch", value.protocol_epoch},
          {"tip_event_id", fixed_hex(value.tip_event_id)}};
}

AnchorCheckpoint parse_checkpoint(const json& value) {
  require_exact_fields(value,
                       {"accepted_head", "accepted_clock", "cloud_revision",
                        "format_version", "head_envelope_hash",
                        "last_checkpoint_created_at", "protocol_epoch",
                        "tip_event_id"},
                       "checkpoint");
  AnchorCheckpoint result;
  result.format_version = value.at("format_version").get<uint8_t>();
  result.accepted_head =
      fixed_from_hex<32>(value.at("accepted_head"), "accepted_head");
  result.accepted_clock =
      parse_clock(value.at("accepted_clock"), "accepted_clock");
  result.protocol_epoch = value.at("protocol_epoch").get<uint64_t>();
  result.head_envelope_hash = fixed_from_hex<32>(
      value.at("head_envelope_hash"), "head_envelope_hash");
  result.last_checkpoint_created_at =
      value.at("last_checkpoint_created_at").get<uint64_t>();
  result.tip_event_id =
      fixed_from_hex<32>(value.at("tip_event_id"), "tip_event_id");
  result.cloud_revision = value.at("cloud_revision").get<std::string>();
  if (result.format_version != 2 || result.cloud_revision.empty()) {
    throw std::runtime_error("unsupported or invalid checkpoint");
  }
  return result;
}

json prepared_json(const PreparedWriteRecord& value) {
  json result = {
      {"cloud_revision", value.cloud_revision},
      {"encrypted_head", to_hex(value.encrypted_head_bytes)},
      {"format_version", value.format_version},
      {"new_head", fixed_hex(value.new_head)},
      {"new_clock", clock_json(value.new_clock)},
      {"operation_id", fixed_hex(value.operation_id)},
      {"phase", prepared_write_phase_name(value.phase)},
      {"previous_head", fixed_hex(value.previous_head)},
      {"previous_clock", clock_json(value.previous_clock)},
      {"protocol_epoch", value.protocol_epoch},
  };
  result["observation_event_id"] = value.observation_event_id.has_value()
                                       ? json(fixed_hex(*value.observation_event_id))
                                       : json(nullptr);
  result["proposal_event_id"] = value.proposal_event_id.has_value()
                                    ? json(fixed_hex(*value.proposal_event_id))
                                    : json(nullptr);
  return result;
}

PreparedWritePhase parse_phase(const std::string& value) {
  if (value == "OBJECTS_PREPARED") return PreparedWritePhase::ObjectsPrepared;
  if (value == "PROPOSAL_PUBLISHED") return PreparedWritePhase::ProposalPublished;
  if (value == "HEAD_UPDATED") return PreparedWritePhase::HeadUpdated;
  if (value == "OBSERVATION_PUBLISHED") return PreparedWritePhase::ObservationPublished;
  throw std::runtime_error("unsupported prepared write phase");
}

PreparedWriteRecord parse_prepared(const json& value) {
  require_exact_fields(
      value,
      {"cloud_revision", "encrypted_head", "format_version", "new_head",
       "new_clock", "observation_event_id", "operation_id", "phase",
       "previous_clock", "previous_head", "proposal_event_id",
       "protocol_epoch"},
      "prepared write");
  PreparedWriteRecord result;
  result.format_version = value.at("format_version").get<uint8_t>();
  result.operation_id =
      fixed_from_hex<16>(value.at("operation_id"), "operation_id");
  result.previous_head =
      fixed_from_hex<32>(value.at("previous_head"), "previous_head");
  result.new_head = fixed_from_hex<32>(value.at("new_head"), "new_head");
  result.previous_clock =
      parse_clock(value.at("previous_clock"), "previous_clock");
  result.new_clock = parse_clock(value.at("new_clock"), "new_clock");
  result.protocol_epoch = value.at("protocol_epoch").get<uint64_t>();
  result.encrypted_head_bytes =
      from_hex(value.at("encrypted_head").get<std::string>());
  result.phase = parse_phase(value.at("phase").get<std::string>());
  result.cloud_revision = value.at("cloud_revision").get<std::string>();
  if (!value.at("proposal_event_id").is_null()) {
    result.proposal_event_id = fixed_from_hex<32>(
        value.at("proposal_event_id"), "proposal_event_id");
  }
  if (!value.at("observation_event_id").is_null()) {
    result.observation_event_id = fixed_from_hex<32>(
        value.at("observation_event_id"), "observation_event_id");
  }
  if (result.format_version != 2 || result.encrypted_head_bytes.empty() ||
      compare_vector_clocks(result.previous_clock, result.new_clock) !=
          VectorClockRelation::Before) {
    throw std::runtime_error("unsupported or invalid prepared write");
  }
  return result;
}

bool events_equal(const SignedNostrEvent& left,
                  const SignedNostrEvent& right) {
  return serialize_nostr_event_json(left) == serialize_nostr_event_json(right);
}

std::vector<std::filesystem::path> json_files(
    const std::filesystem::path& directory,
    size_t limit) {
  std::vector<std::filesystem::path> paths;
  std::error_code error;
  for (std::filesystem::directory_iterator iterator(directory, error), end;
       !error && iterator != end; iterator.increment(error)) {
    if (iterator->is_regular_file() && iterator->path().extension() == ".json") {
      paths.push_back(iterator->path());
      if (paths.size() > limit) {
        throw std::runtime_error("anchor event limit exceeded");
      }
    }
  }
  if (error) {
    throw std::runtime_error("failed to enumerate trust directory: " +
                             error.message());
  }
  std::sort(paths.begin(), paths.end());
  return paths;
}
}  // namespace

AnchorTrustStore::AnchorTrustStore(std::filesystem::path trust_directory,
                                   ByteVec mac_key)
    : trust_directory_(std::move(trust_directory)),
      mac_key_(std::move(mac_key)) {
  if (trust_directory_.empty() || mac_key_.size() != 32) {
    throw std::runtime_error("invalid anchor trust store configuration");
  }
  ensure_directories();
}

bool AnchorTrustStore::channel_exists() const {
  return std::filesystem::exists(authenticated_path("channel.json"));
}

void AnchorTrustStore::save_channel(const AnchorChannelConfig& config) const {
  write_authenticated(authenticated_path("channel.json"), "channel",
                      channel_json(config), mac_key_);
}

AnchorChannelConfig AnchorTrustStore::load_channel() const {
  return parse_channel(read_authenticated(authenticated_path("channel.json"),
                                          "channel", mac_key_));
}

bool AnchorTrustStore::checkpoint_exists() const {
  return std::filesystem::exists(authenticated_path("checkpoint.json"));
}

void AnchorTrustStore::save_checkpoint(
    const AnchorCheckpoint& checkpoint) const {
  write_authenticated(authenticated_path("checkpoint.json"), "checkpoint",
                      checkpoint_json(checkpoint), mac_key_);
}

AnchorCheckpoint AnchorTrustStore::load_checkpoint() const {
  return parse_checkpoint(read_authenticated(
      authenticated_path("checkpoint.json"), "checkpoint", mac_key_));
}

bool AnchorTrustStore::prepared_exists() const {
  return std::filesystem::exists(authenticated_path("prepared.json"));
}

void AnchorTrustStore::save_prepared(
    const PreparedWriteRecord& prepared) const {
  write_authenticated(authenticated_path("prepared.json"), "prepared",
                      prepared_json(prepared), mac_key_);
}

PreparedWriteRecord AnchorTrustStore::load_prepared() const {
  return parse_prepared(read_authenticated(authenticated_path("prepared.json"),
                                           "prepared", mac_key_));
}

void AnchorTrustStore::clear_prepared() const {
  const auto path = authenticated_path("prepared.json");
  std::error_code error;
  const bool removed = std::filesystem::remove(path, error);
  if (error) {
    throw std::runtime_error("failed to remove prepared journal: " +
                             error.message());
  }
  if (removed) sync_directory(path.parent_path());
}

void AnchorTrustStore::cache_event(const SignedNostrEvent& event) const {
  ensure_directories();
  const auto path = event_directory() / (to_hex(event.id) + ".json");
  const std::string encoded = serialize_nostr_event_json(event);
  if (std::filesystem::exists(path)) {
    const SignedNostrEvent existing =
        deserialize_nostr_event_json(read_small_text(path));
    if (!events_equal(existing, event)) {
      throw std::runtime_error("immutable cached event conflict: " +
                               to_hex(event.id));
    }
    return;
  }
  write_secure_atomic(path, encoded);
}

std::vector<SignedNostrEvent> AnchorTrustStore::load_cached_events(
    size_t limit) const {
  ensure_directories();
  std::vector<SignedNostrEvent> result;
  for (const auto& path : json_files(event_directory(), limit)) {
    SignedNostrEvent event =
        deserialize_nostr_event_json(read_small_text(path));
    if (path.stem().string() != to_hex(event.id)) {
      throw std::runtime_error("cached event filename does not match ID");
    }
    result.push_back(std::move(event));
  }
  return result;
}

void AnchorTrustStore::save_witness(
    const ReplicaId& replica_id,
    const SignedNostrEvent& event) const {
  ensure_directories();
  if (event.kind != kGitVaultCheckpointEventKind) {
    throw std::runtime_error("witness must be a checkpoint event");
  }
  write_authenticated(
      witness_directory() / (fixed_hex(replica_id) + ".json"), "witness",
      json{{"event", json::parse(serialize_nostr_event_json(event))}},
      mac_key_);
}

std::vector<SignedNostrEvent> AnchorTrustStore::load_witnesses(
    size_t limit) const {
  ensure_directories();
  std::vector<SignedNostrEvent> result;
  for (const auto& path : json_files(witness_directory(), limit)) {
    const json payload = read_authenticated(path, "witness", mac_key_);
    require_exact_fields(payload, {"event"}, "witness");
    SignedNostrEvent event =
        deserialize_nostr_event_json(payload.at("event").dump());
    const std::string replica = path.stem().string();
    if (event.kind != kGitVaultCheckpointEventKind || replica.size() != 32 ||
        from_hex(replica).size() != 16) {
      throw std::runtime_error("invalid cached witness event");
    }
    result.push_back(std::move(event));
  }
  return result;
}

void AnchorTrustStore::save_outbox(const AnchorOutboxRecord& record) const {
  ensure_directories();
  const json payload = {
      {"accepted_endpoints",
       std::vector<std::string>(record.accepted_endpoints.begin(),
                                record.accepted_endpoints.end())},
      {"event", json::parse(serialize_nostr_event_json(record.event))},
  };
  write_authenticated(outbox_directory() / (to_hex(record.event.id) + ".json"),
                      "outbox", payload, mac_key_);
}

std::vector<AnchorOutboxRecord> AnchorTrustStore::load_outbox(
    size_t limit) const {
  ensure_directories();
  std::vector<AnchorOutboxRecord> result;
  for (const auto& path : json_files(outbox_directory(), limit)) {
    const json payload = read_authenticated(path, "outbox", mac_key_);
    require_exact_fields(payload, {"accepted_endpoints", "event"}, "outbox");
    AnchorOutboxRecord record;
    record.event = deserialize_nostr_event_json(payload.at("event").dump());
    if (path.stem().string() != to_hex(record.event.id)) {
      throw std::runtime_error("outbox filename does not match event ID");
    }
    const auto endpoints =
        payload.at("accepted_endpoints").get<std::vector<std::string>>();
    record.accepted_endpoints.insert(endpoints.begin(), endpoints.end());
    result.push_back(std::move(record));
  }
  return result;
}

void AnchorTrustStore::remove_outbox(const AnchorHash& event_id) const {
  const auto path = outbox_directory() / (to_hex(event_id) + ".json");
  std::error_code error;
  const bool removed = std::filesystem::remove(path, error);
  if (error) {
    throw std::runtime_error("failed to remove outbox event: " +
                             error.message());
  }
  if (removed) sync_directory(path.parent_path());
}

const std::filesystem::path& AnchorTrustStore::trust_directory() const {
  return trust_directory_;
}

std::filesystem::path AnchorTrustStore::authenticated_path(
    const char* name) const {
  return trust_directory_ / name;
}

std::filesystem::path AnchorTrustStore::event_directory() const {
  return trust_directory_ / "events";
}

std::filesystem::path AnchorTrustStore::outbox_directory() const {
  return trust_directory_ / "outbox";
}

std::filesystem::path AnchorTrustStore::witness_directory() const {
  return trust_directory_ / "witnesses";
}

void AnchorTrustStore::ensure_directories() const {
  protect_directory(trust_directory_);
  protect_directory(event_directory());
  protect_directory(outbox_directory());
  protect_directory(witness_directory());
}

const char* prepared_write_phase_name(PreparedWritePhase phase) {
  switch (phase) {
    case PreparedWritePhase::ObjectsPrepared:
      return "OBJECTS_PREPARED";
    case PreparedWritePhase::ProposalPublished:
      return "PROPOSAL_PUBLISHED";
    case PreparedWritePhase::HeadUpdated:
      return "HEAD_UPDATED";
    case PreparedWritePhase::ObservationPublished:
      return "OBSERVATION_PUBLISHED";
  }
  return "UNKNOWN";
}

std::string serialize_anchor_channel_config(
    const AnchorChannelConfig& config) {
  return channel_json(config).dump();
}

AnchorChannelConfig deserialize_anchor_channel_config(
    const std::string& canonical_json) {
  const json parsed = json::parse(canonical_json);
  if (parsed.dump() != canonical_json) {
    throw std::runtime_error("channel config JSON is not canonical");
  }
  return parse_channel(parsed);
}

std::string serialize_anchor_checkpoint(
    const AnchorCheckpoint& checkpoint) {
  return checkpoint_json(checkpoint).dump();
}

AnchorCheckpoint deserialize_anchor_checkpoint(
    const std::string& canonical_json) {
  const json parsed = json::parse(canonical_json);
  if (parsed.dump() != canonical_json) {
    throw std::runtime_error("checkpoint JSON is not canonical");
  }
  return parse_checkpoint(parsed);
}
