#include "nostr_anchor_channel.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <future>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <openssl/ssl.h>

#include "json.hpp"
#include "util.h"

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = asio::ssl;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;
using nlohmann::json;

struct RelayUrl {
  std::string original;
  std::string scheme;
  std::string host;
  std::string port;
  std::string target;
};

struct RelayFetchAttempt {
  AnchorFetchEndpointResult endpoint;
  std::vector<SignedNostrEvent> events;
};

RelayUrl parse_relay_url(const std::string& value) {
  const size_t scheme_end = value.find("://");
  if (scheme_end == std::string::npos) {
    throw std::runtime_error("relay URL must start with wss:// or ws://: " +
                             value);
  }
  RelayUrl result;
  result.original = value;
  result.scheme = value.substr(0, scheme_end);
  if (result.scheme != "wss" && result.scheme != "ws") {
    throw std::runtime_error("unsupported relay URL scheme: " + value);
  }
  const size_t authority_start = scheme_end + 3;
  const size_t target_start = value.find('/', authority_start);
  const std::string authority = value.substr(
      authority_start, target_start == std::string::npos
                           ? std::string::npos
                           : target_start - authority_start);
  result.target = target_start == std::string::npos
                      ? "/"
                      : value.substr(target_start);
  if (authority.empty() || authority.find('@') != std::string::npos ||
      result.target.find('#') != std::string::npos) {
    throw std::runtime_error("invalid relay URL: " + value);
  }

  if (authority.front() == '[') {
    const size_t bracket = authority.find(']');
    if (bracket == std::string::npos) {
      throw std::runtime_error("invalid relay IPv6 URL: " + value);
    }
    result.host = authority.substr(1, bracket - 1);
    if (bracket + 1 < authority.size()) {
      if (authority[bracket + 1] != ':') {
        throw std::runtime_error("invalid relay URL port: " + value);
      }
      result.port = authority.substr(bracket + 2);
    }
  } else {
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      result.host = authority.substr(0, colon);
      result.port = authority.substr(colon + 1);
    } else {
      result.host = authority;
    }
  }
  if (result.host.empty()) {
    throw std::runtime_error("relay URL host is empty: " + value);
  }
  if (result.scheme == "ws" && result.host != "127.0.0.1" &&
      result.host != "localhost" && result.host != "::1") {
    throw std::runtime_error(
        "unencrypted ws:// relays are allowed only on loopback: " + value);
  }
  if (result.port.empty()) {
    result.port = result.scheme == "wss" ? "443" : "80";
  }
  if (!std::all_of(result.port.begin(), result.port.end(), ::isdigit)) {
    throw std::runtime_error("invalid relay URL port: " + value);
  }
  return result;
}

std::string host_header(const RelayUrl& relay) {
  const bool default_port =
      (relay.scheme == "wss" && relay.port == "443") ||
      (relay.scheme == "ws" && relay.port == "80");
  return default_port ? relay.host : relay.host + ":" + relay.port;
}

std::string event_message(std::string_view command,
                          const SignedNostrEvent& event) {
  json result = json::array();
  result.push_back(command);
  result.push_back(json::parse(serialize_nostr_event_json(event)));
  return result.dump();
}

SignedNostrEvent make_auth_event(const RelayUrl& relay,
                                 const std::string& challenge,
                                 const std::array<uint8_t, 32>& secret) {
  UnsignedNostrEvent auth;
  auth.created_at = static_cast<uint64_t>(std::time(nullptr));
  auth.kind = 22242;
  auth.tags = {{"relay", relay.original}, {"challenge", challenge}};
  return sign_nostr_event(auth, secret);
}

std::string make_filter(const AnchorChannelQuery& query) {
  json filter = json::object();
  if (query.author.has_value()) {
    filter["authors"] = json::array({to_hex(*query.author)});
  }
  if (query.kind.has_value()) {
    filter["kinds"] = json::array({*query.kind});
  }
  for (const auto& tag : query.required_tags) {
    if (tag.size() != 2 || tag[0].size() != 1) {
      throw std::runtime_error(
          "Nostr relay filters require two-element, single-letter tags");
    }
    filter["#" + tag[0]] = json::array({tag[1]});
  }
  return filter.dump();
}

void require_array_message(const json& message, size_t minimum_size) {
  if (!message.is_array() || message.size() < minimum_size ||
      !message[0].is_string()) {
    throw std::runtime_error("relay returned a malformed NIP-01 message");
  }
}

template <typename WebSocket>
void configure_websocket(WebSocket& ws,
                         const NostrAnchorChannelOptions& options) {
  ws.read_message_max(options.maximum_frame_bytes);
  websocket::stream_base::timeout timeout;
  timeout.handshake_timeout = options.connect_timeout;
  timeout.idle_timeout = options.operation_timeout;
  timeout.keep_alive_pings = false;
  ws.set_option(timeout);
  ws.set_option(websocket::stream_base::decorator(
      [](websocket::request_type& request) {
        request.set(boost::beast::http::field::user_agent,
                    "GitVault-Nostr/1");
      }));
}

// Beast timeouts apply to asynchronous operations. Drive each operation to
// completion on this connection's private io_context.
template <typename Stream, typename Start>
void run_io(Stream& stream, Start start) {
  auto& io = static_cast<asio::io_context&>(stream.get_executor().context());
  io.restart();
  beast::error_code error;
  bool completed = false;
  start([&](beast::error_code result, auto&&...) {
    error = result;
    completed = true;
  });
  while (!completed) io.run_one();
  if (error) throw beast::system_error(error);
}

template <typename WebSocket>
json read_message(WebSocket& ws) {
  beast::flat_buffer buffer;
  run_io(ws, [&](auto done) { ws.async_read(buffer, done); });
  const std::string encoded = beast::buffers_to_string(buffer.data());
  try {
    return json::parse(encoded);
  } catch (const std::exception& error) {
    throw std::runtime_error(std::string("relay returned invalid JSON: ") +
                             error.what());
  }
}

template <typename WebSocket>
void send_text(WebSocket& ws, const std::string& message) {
  ws.text(true);
  run_io(ws, [&](auto done) { ws.async_write(asio::buffer(message), done); });
}

template <typename WebSocket>
AnchorPublishStatus publish_over_socket(
    WebSocket& ws,
    const RelayUrl& relay,
    const SignedNostrEvent& event,
    const std::array<uint8_t, 32>& secret,
    std::string& response_message) {
  const std::string expected_id = to_hex(event.id);
  send_text(ws, event_message("EVENT", event));
  bool authenticated = false;
  for (;;) {
    const json response = read_message(ws);
    require_array_message(response, 2);
    const std::string type = response[0].get<std::string>();
    if (type == "AUTH") {
      if (authenticated || !response[1].is_string()) {
        throw std::runtime_error("relay returned an invalid AUTH challenge");
      }
      const SignedNostrEvent auth = make_auth_event(
          relay, response[1].get<std::string>(), secret);
      send_text(ws, event_message("AUTH", auth));
      authenticated = true;
      send_text(ws, event_message("EVENT", event));
      continue;
    }
    if (type != "OK") {
      continue;
    }
    require_array_message(response, 4);
    if (!response[1].is_string() ||
        response[1].get<std::string>() != expected_id) {
      continue;
    }
    if (!response[2].is_boolean() || !response[3].is_string()) {
      throw std::runtime_error("relay returned a malformed OK message");
    }
    response_message = response[3].get<std::string>();
    if (response[2].get<bool>()) {
      return response_message.rfind("duplicate", 0) == 0
                 ? AnchorPublishStatus::AlreadyPresent
                 : AnchorPublishStatus::Accepted;
    }
    return AnchorPublishStatus::Rejected;
  }
}

template <typename WebSocket>
std::vector<SignedNostrEvent> fetch_over_socket(
    WebSocket& ws,
    const RelayUrl& relay,
    const AnchorChannelQuery& query,
    const std::array<uint8_t, 32>& secret,
    const NostrAnchorChannelOptions& options) {
  const std::string subscription_id = to_hex(random_bytes(8));
  json request = json::array({"REQ", subscription_id,
                              json::parse(make_filter(query))});
  send_text(ws, request.dump());
  std::vector<SignedNostrEvent> result;
  std::map<std::string, std::string> exact_events;
  bool authenticated = false;
  for (;;) {
    const json response = read_message(ws);
    require_array_message(response, 2);
    const std::string type = response[0].get<std::string>();
    if (type == "AUTH") {
      if (authenticated || !response[1].is_string()) {
        throw std::runtime_error("relay returned an invalid AUTH challenge");
      }
      const SignedNostrEvent auth = make_auth_event(
          relay, response[1].get<std::string>(), secret);
      send_text(ws, event_message("AUTH", auth));
      authenticated = true;
      send_text(ws, request.dump());
      continue;
    }
    if (type == "EOSE") {
      if (response[1].is_string() &&
          response[1].get<std::string>() == subscription_id) {
        send_text(ws, json::array({"CLOSE", subscription_id}).dump());
        return result;
      }
      continue;
    }
    if (type == "CLOSED") {
      if (response.size() >= 3 && response[1].is_string() &&
          response[1].get<std::string>() == subscription_id) {
        const std::string reason = response[2].is_string()
                                       ? response[2].get<std::string>()
                                       : std::string{};
        throw std::runtime_error("relay closed subscription: " + reason);
      }
      continue;
    }
    if (type != "EVENT") {
      continue;
    }
    require_array_message(response, 3);
    if (!response[1].is_string() ||
        response[1].get<std::string>() != subscription_id ||
        !response[2].is_object()) {
      continue;
    }
    const std::string exact = response[2].dump();
    SignedNostrEvent event = deserialize_nostr_event_json(exact);
    if (event.content.size() > options.maximum_content_bytes) {
      throw std::runtime_error("relay event content exceeds GitVault limit");
    }
    const std::string id = to_hex(event.id);
    const auto existing = exact_events.find(id);
    if (existing != exact_events.end()) {
      if (existing->second != serialize_nostr_event_json(event)) {
        throw std::runtime_error(
            "relay returned different bytes for one event ID");
      }
      continue;
    }
    if (result.size() >= options.maximum_events) {
      throw std::runtime_error("relay event count exceeds GitVault limit");
    }
    exact_events.emplace(id, serialize_nostr_event_json(event));
    result.push_back(std::move(event));
  }
}

template <typename Operation>
auto with_relay_socket(const RelayUrl& relay,
                       const NostrAnchorChannelOptions& options,
                       Operation operation) {
  asio::io_context io;
  tcp::resolver resolver(io);
  tcp::resolver::results_type endpoints;
  asio::steady_timer resolve_timer(io);
  resolve_timer.expires_after(options.connect_timeout);
  bool resolve_timed_out = false;
  resolve_timer.async_wait([&](beast::error_code error) {
    if (!error) {
      resolve_timed_out = true;
      resolver.cancel();
    }
  });
  beast::error_code resolve_error;
  resolver.async_resolve(relay.host, relay.port,
      [&](beast::error_code error, tcp::resolver::results_type result) {
        resolve_error = error;
        endpoints = std::move(result);
        resolve_timer.cancel();
      });
  io.run();
  if (resolve_timed_out) throw beast::system_error(beast::error::timeout);
  if (resolve_error) throw beast::system_error(resolve_error);
  if (relay.scheme == "ws") {
    websocket::stream<beast::tcp_stream> ws(io);
    configure_websocket(ws, options);
    beast::get_lowest_layer(ws).expires_after(options.connect_timeout);
    run_io(ws, [&](auto done) {
      beast::get_lowest_layer(ws).async_connect(endpoints, done);
    });
    beast::get_lowest_layer(ws).expires_never();
    run_io(ws, [&](auto done) {
      ws.async_handshake(host_header(relay), relay.target, done);
    });
    auto result = operation(ws);
    beast::error_code ignored;
    beast::get_lowest_layer(ws).socket().close(ignored);
    return result;
  }

  ssl::context context(ssl::context::tls_client);
  context.set_default_verify_paths();
  websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws(io, context);
  configure_websocket(ws, options);
  ws.next_layer().set_verify_mode(ssl::verify_peer);
  ws.next_layer().set_verify_callback(ssl::host_name_verification(relay.host));
  if (!SSL_set_tlsext_host_name(ws.next_layer().native_handle(),
                                relay.host.c_str())) {
    throw beast::system_error(
        static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category());
  }
  beast::get_lowest_layer(ws).expires_after(options.connect_timeout);
  run_io(ws, [&](auto done) {
    beast::get_lowest_layer(ws).async_connect(endpoints, done);
  });
  beast::get_lowest_layer(ws).expires_after(options.connect_timeout);
  run_io(ws, [&](auto done) {
    ws.next_layer().async_handshake(ssl::stream_base::client, done);
  });
  beast::get_lowest_layer(ws).expires_never();
  run_io(ws, [&](auto done) {
      ws.async_handshake(host_header(relay), relay.target, done);
    });
  auto result = operation(ws);
  beast::error_code ignored;
  beast::get_lowest_layer(ws).socket().close(ignored);
  return result;
}

AnchorPublishReceipt publish_one(
    const std::string& endpoint,
    const SignedNostrEvent& event,
    const std::array<uint8_t, 32>& secret,
    const NostrAnchorChannelOptions& options) {
  AnchorPublishReceipt receipt;
  receipt.endpoint = endpoint;
  receipt.event_id = event.id;
  const auto started = std::chrono::steady_clock::now();
  try {
    const RelayUrl relay = parse_relay_url(endpoint);
    receipt.status = with_relay_socket(
        relay, options, [&](auto& ws) {
          return publish_over_socket(ws, relay, event, secret,
                                     receipt.message);
        });
  } catch (const beast::system_error& error) {
    receipt.status = error.code() == beast::error::timeout
                         ? AnchorPublishStatus::Timeout
                         : AnchorPublishStatus::TransportError;
    receipt.message = error.what();
  } catch (const std::exception& error) {
    receipt.status = AnchorPublishStatus::TransportError;
    receipt.message = error.what();
  }
  receipt.latency_milliseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started)
          .count());
  return receipt;
}

RelayFetchAttempt fetch_one(
    const std::string& endpoint,
    const AnchorChannelQuery& query,
    const std::array<uint8_t, 32>& secret,
    const NostrAnchorChannelOptions& options) {
  RelayFetchAttempt attempt;
  attempt.endpoint.endpoint = endpoint;
  const auto started = std::chrono::steady_clock::now();
  try {
    const RelayUrl relay = parse_relay_url(endpoint);
    attempt.events = with_relay_socket(
        relay, options, [&](auto& ws) {
          return fetch_over_socket(ws, relay, query, secret, options);
        });
    attempt.endpoint.status = AnchorFetchStatus::Synchronized;
  } catch (const beast::system_error& error) {
    attempt.endpoint.status = error.code() == beast::error::timeout
                                  ? AnchorFetchStatus::Timeout
                                  : AnchorFetchStatus::TransportError;
    attempt.endpoint.message = error.what();
  } catch (const std::exception& error) {
    attempt.endpoint.status = AnchorFetchStatus::Rejected;
    attempt.endpoint.message = error.what();
  }
  attempt.endpoint.latency_milliseconds = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started)
          .count());
  return attempt;
}
}  // namespace

NostrAnchorChannel::NostrAnchorChannel(
    std::vector<std::string> relay_urls,
    std::array<uint8_t, 32> signing_secret,
    NostrAnchorChannelOptions options)
    : relay_urls_(std::move(relay_urls)),
      signing_secret_(signing_secret),
      options_(options) {
  if (relay_urls_.empty()) {
    throw std::runtime_error("at least one Nostr relay is required");
  }
  std::set<std::string> unique;
  for (const auto& endpoint : relay_urls_) {
    (void)parse_relay_url(endpoint);
    if (!unique.insert(endpoint).second) {
      throw std::runtime_error("duplicate Nostr relay URL: " + endpoint);
    }
  }
  if (options_.maximum_events == 0 || options_.maximum_frame_bytes == 0 ||
      options_.maximum_content_bytes == 0) {
    throw std::runtime_error("Nostr channel limits must be positive");
  }
}

AnchorPublishResult NostrAnchorChannel::publish(
    const SignedNostrEvent& event) {
  std::vector<std::future<AnchorPublishReceipt>> pending;
  for (const auto& endpoint : relay_urls_) {
    pending.push_back(std::async(std::launch::async, publish_one, endpoint,
                                 event, signing_secret_, options_));
  }
  AnchorPublishResult result;
  for (auto& operation : pending) {
    result.endpoints.push_back(operation.get());
  }
  return result;
}

AnchorFetchResult NostrAnchorChannel::fetch(
    const AnchorChannelQuery& query) const {
  (void)make_filter(query);
  std::vector<std::future<RelayFetchAttempt>> pending;
  for (const auto& endpoint : relay_urls_) {
    pending.push_back(std::async(std::launch::async, fetch_one, endpoint,
                                 query, signing_secret_, options_));
  }

  AnchorFetchResult result;
  std::map<std::string, std::string> exact_by_id;
  for (auto& operation : pending) {
    RelayFetchAttempt attempt = operation.get();
    result.endpoints.push_back(std::move(attempt.endpoint));
    for (auto& event : attempt.events) {
      const std::string id = to_hex(event.id);
      const std::string exact = serialize_nostr_event_json(event);
      const auto existing = exact_by_id.find(id);
      if (existing != exact_by_id.end()) {
        if (existing->second != exact) {
          throw std::runtime_error(
              "Nostr relays returned different bytes for one event ID: " +
              id);
        }
        continue;
      }
      if (result.events.size() >= options_.maximum_events) {
        throw std::runtime_error(
            "combined relay event count exceeds GitVault limit");
      }
      exact_by_id.emplace(id, exact);
      result.events.push_back(std::move(event));
    }
  }
  std::sort(result.events.begin(), result.events.end(),
            [](const SignedNostrEvent& left,
               const SignedNostrEvent& right) { return left.id < right.id; });
  return result;
}

const std::vector<std::string>& NostrAnchorChannel::relay_urls() const {
  return relay_urls_;
}
