#include "local_file_anchor_channel.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <utility>

#include "util.h"

namespace {
bool events_equal(const SignedNostrEvent& left,
                  const SignedNostrEvent& right) {
  return left.id == right.id && left.public_key == right.public_key &&
         left.created_at == right.created_at && left.kind == right.kind &&
         left.tags == right.tags && left.content == right.content &&
         left.signature == right.signature;
}

bool matches_query(const SignedNostrEvent& event,
                   const AnchorChannelQuery& query) {
  if (query.author.has_value() && event.public_key != *query.author) {
    return false;
  }
  if (query.kind.has_value() && event.kind != *query.kind) {
    return false;
  }
  return std::all_of(
      query.required_tags.begin(), query.required_tags.end(),
      [&](const NostrTag& required_tag) {
        return std::find(event.tags.begin(), event.tags.end(), required_tag) !=
               event.tags.end();
      });
}

SignedNostrEvent read_stored_event(const std::filesystem::path& path) {
  const ByteVec bytes = read_file_bytes(path);
  const std::string encoded(bytes.begin(), bytes.end());
  SignedNostrEvent event = deserialize_nostr_event_json(encoded);
  if (path.stem().string() != to_hex(event.id)) {
    throw std::runtime_error(
        "anchor event filename does not match its event ID: " +
        path.string());
  }
  return event;
}

AnchorPublishStatus existing_event_status(
    const std::filesystem::path& path,
    const SignedNostrEvent& event) {
  try {
    if (events_equal(read_stored_event(path), event)) {
      return AnchorPublishStatus::AlreadyPresent;
    }
  } catch (const std::exception&) {
    // A malformed existing file is still an immutable conflict. Do not replace it.
  }
  throw std::runtime_error(
      "different anchor event already exists for ID: " + to_hex(event.id));
}
}  // namespace

LocalFileAnchorChannel::LocalFileAnchorChannel(
    std::filesystem::path root_directory)
    : root_directory_(std::move(root_directory)) {
  if (root_directory_.empty()) {
    throw std::runtime_error("local anchor channel root must not be empty");
  }
  ensure_event_directory();
}

AnchorPublishResult LocalFileAnchorChannel::publish(
    const SignedNostrEvent& event) {
  ensure_event_directory();
  const std::filesystem::path target =
      event_directory() / (to_hex(event.id) + ".json");

  if (std::filesystem::exists(target)) {
    return {{{root_directory_.string(), event.id,
              existing_event_status(target, event), {}, 0}}};
  }

  std::filesystem::path temporary = target;
  temporary += ".tmp-" + to_hex(random_bytes(8));
  try {
    const std::string encoded = serialize_nostr_event_json(event);
    write_file_bytes(temporary, ByteVec(encoded.begin(), encoded.end()));

    std::error_code install_error;
    std::filesystem::create_hard_link(temporary, target, install_error);
    std::error_code cleanup_error;
    std::filesystem::remove(temporary, cleanup_error);

    if (!install_error) {
      return {{{root_directory_.string(), event.id,
                AnchorPublishStatus::Accepted, {}, 0}}};
    }
    if (std::filesystem::exists(target)) {
      return {{{root_directory_.string(), event.id,
                existing_event_status(target, event), {}, 0}}};
    }
    throw std::runtime_error("failed to install anchor event: " +
                             install_error.message());
  } catch (...) {
    std::error_code cleanup_error;
    std::filesystem::remove(temporary, cleanup_error);
    throw;
  }
}

AnchorFetchResult LocalFileAnchorChannel::fetch(
    const AnchorChannelQuery& query) const {
  ensure_event_directory();
  std::vector<std::filesystem::path> event_paths;
  std::error_code iteration_error;
  for (std::filesystem::directory_iterator iterator(event_directory(),
                                                     iteration_error),
       end;
       !iteration_error && iterator != end;
       iterator.increment(iteration_error)) {
    if (iterator->is_regular_file() && iterator->path().extension() == ".json") {
      event_paths.push_back(iterator->path());
    }
  }
  if (iteration_error) {
    throw std::runtime_error("failed to enumerate local anchor events: " +
                             iteration_error.message());
  }
  std::sort(event_paths.begin(), event_paths.end());

  std::vector<SignedNostrEvent> events;
  for (const auto& path : event_paths) {
    SignedNostrEvent event = read_stored_event(path);
    if (matches_query(event, query)) {
      events.push_back(std::move(event));
    }
  }
  AnchorFetchResult result;
  result.events = std::move(events);
  result.endpoints.push_back(
      {root_directory_.string(), AnchorFetchStatus::Synchronized, {}, 0});
  return result;
}

const std::filesystem::path& LocalFileAnchorChannel::root_directory() const {
  return root_directory_;
}

std::filesystem::path LocalFileAnchorChannel::event_directory() const {
  return root_directory_ / "events";
}

void LocalFileAnchorChannel::ensure_event_directory() const {
  std::error_code error;
  std::filesystem::create_directories(event_directory(), error);
  if (error) {
    throw std::runtime_error("failed to create local anchor channel: " +
                             error.message());
  }
}
