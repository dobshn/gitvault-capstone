#include "nostr_anchor_channel.h"
#include "relay_selection.h"
#include "nostr_event.h"
#include "json.hpp"
#include "util.h"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include <algorithm>
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = boost::beast::websocket;
using tcp = asio::ip::tcp;
using nlohmann::json;
int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    ++failures;
  }
}

template <typename Action>
void expect_throw(Action action, const std::string& message) {
  try {
    action();
    std::cerr << "FAIL: " << message << " did not throw\n";
    ++failures;
  } catch (const std::runtime_error&) {
  }
}

std::array<uint8_t, 32> secret(uint8_t value) {
  std::array<uint8_t, 32> result{};
  result.back() = value;
  return result;
}

SignedNostrEvent make_event(const std::array<uint8_t, 32>& signing_secret,
                            const std::string& content) {
  UnsignedNostrEvent event;
  event.created_at = 100;
  event.kind = 9500;
  event.tags = {{"t", std::string(64, 'a')}};
  event.content = content;
  return sign_nostr_event(event, signing_secret);
}

json read_json(websocket::stream<tcp::socket>& ws) {
  beast::flat_buffer buffer;
  ws.read(buffer);
  return json::parse(beast::buffers_to_string(buffer.data()));
}

void write_json(websocket::stream<tcp::socket>& ws, const json& value) {
  const std::string encoded = value.dump();
  ws.text(true);
  ws.write(asio::buffer(encoded));
}

class OneShotRelay {
public:
  using Handler = std::function<void(websocket::stream<tcp::socket>&)>;

  explicit OneShotRelay(Handler handler)
      : acceptor_(io_, {asio::ip::make_address("127.0.0.1"), 0}),
        thread_([this, handler = std::move(handler)] {
          try {
            tcp::socket socket(io_);
            acceptor_.accept(socket);
            websocket::stream<tcp::socket> ws(std::move(socket));
            ws.accept();
            handler(ws);
            beast::error_code ignored;
            ws.close(websocket::close_code::normal, ignored);
          } catch (...) {
            error_ = std::current_exception();
          }
        }) {}

  ~OneShotRelay() {
    if (thread_.joinable()) thread_.join();
  }

  std::string url() const {
    return "ws://127.0.0.1:" +
           std::to_string(acceptor_.local_endpoint().port()) + "/";
  }

  void finish() {
    if (thread_.joinable()) thread_.join();
    if (error_) std::rethrow_exception(error_);
  }

private:
  asio::io_context io_;
  tcp::acceptor acceptor_;
  std::thread thread_;
  std::exception_ptr error_;
};

void test_publish_waits_for_matching_ok() {
  const auto signing_secret = secret(3);
  const SignedNostrEvent event = make_event(signing_secret, "publish");
  OneShotRelay relay([&](websocket::stream<tcp::socket>& ws) {
    const json request = read_json(ws);
    expect(request[0] == "EVENT" &&
               request[1]["id"] == to_hex(event.id),
           "publish sends a NIP-01 EVENT frame");
    write_json(ws, json::array(
                       {"OK", to_hex(event.id), true, "saved"}));
  });
  NostrAnchorChannel channel({relay.url()}, signing_secret);
  const AnchorPublishResult result = channel.publish(event);
  expect(result.accepted_count() == 1 &&
             result.endpoints[0].status == AnchorPublishStatus::Accepted,
         "only matching OK=true is counted as a publish ACK");
  relay.finish();
}

void test_fetch_uses_filter_deduplicates_and_waits_for_eose() {
  const auto signing_secret = secret(3);
  const SignedNostrEvent event = make_event(signing_secret, "fetch");
  OneShotRelay relay([&](websocket::stream<tcp::socket>& ws) {
    const json request = read_json(ws);
    expect(request[0] == "REQ" &&
               request[2]["authors"][0] == to_hex(event.public_key) &&
               request[2]["kinds"][0] == 9500 &&
               request[2]["#t"][0] == std::string(64, 'a'),
           "fetch sends author, kind, and #t filters");
    const std::string subscription = request[1].get<std::string>();
    const json encoded = json::parse(serialize_nostr_event_json(event));
    write_json(ws, json::array({"EVENT", subscription, encoded}));
    write_json(ws, json::array({"EVENT", subscription, encoded}));
    write_json(ws, json::array({"EOSE", subscription}));
    (void)read_json(ws);  // CLOSE
  });
  NostrAnchorChannel channel({relay.url()}, signing_secret);
  AnchorChannelQuery query;
  query.author = event.public_key;
  query.kind = 9500;
  query.required_tags = {{"t", std::string(64, 'a')}};
  const AnchorFetchResult result = channel.fetch(query);
  expect(result.synchronized_count() == 1 && result.events.size() == 1 &&
             result.events[0].id == event.id,
         "fetch counts EOSE and deduplicates replayed event IDs");
  relay.finish();
}

void test_nip42_auth_challenge_is_signed_then_operation_retried() {
  const auto signing_secret = secret(3);
  const SignedNostrEvent event = make_event(signing_secret, "auth");
  std::string relay_url;
  OneShotRelay relay([&](websocket::stream<tcp::socket>& ws) {
    const json initial = read_json(ws);
    expect(initial[0] == "EVENT", "operation is attempted before AUTH");
    write_json(ws, json::array({"AUTH", "challenge-123"}));
    const json auth_frame = read_json(ws);
    const SignedNostrEvent auth =
        deserialize_nostr_event_json(auth_frame[1].dump());
    expect(auth_frame[0] == "AUTH" && auth.kind == 22242 &&
               verify_nostr_event(auth, schnorr_public_key(signing_secret)) &&
               std::find(auth.tags.begin(), auth.tags.end(),
                         NostrTag{"challenge", "challenge-123"}) !=
                   auth.tags.end() &&
               std::find(auth.tags.begin(), auth.tags.end(),
                         NostrTag{"relay", relay_url}) != auth.tags.end(),
           "NIP-42 challenge is answered by the Vault key");
    const json retried = read_json(ws);
    expect(retried[0] == "EVENT" && retried[1]["id"] == to_hex(event.id),
           "original operation is retried after AUTH");
    write_json(ws, json::array(
                       {"OK", to_hex(event.id), true, "saved"}));
  });
  relay_url = relay.url();
  NostrAnchorChannel channel({relay_url}, signing_secret);
  expect(channel.publish(event).accepted_count() == 1,
         "authenticated publish succeeds");
  relay.finish();
}

void test_same_id_with_different_bytes_across_relays_is_rejected() {
  const auto signing_secret = secret(3);
  const SignedNostrEvent original = make_event(signing_secret, "original");
  SignedNostrEvent conflicting = original;
  conflicting.content = "different bytes";
  auto handler_for = [](const SignedNostrEvent& event) {
    return [event](websocket::stream<tcp::socket>& ws) {
      const json request = read_json(ws);
      const std::string subscription = request[1].get<std::string>();
      write_json(ws, json::array(
                         {"EVENT", subscription,
                          json::parse(serialize_nostr_event_json(event))}));
      write_json(ws, json::array({"EOSE", subscription}));
      (void)read_json(ws);
    };
  };
  OneShotRelay first(handler_for(original));
  OneShotRelay second(handler_for(conflicting));
  NostrAnchorChannel channel({first.url(), second.url()}, signing_secret);
  expect_throw([&] { (void)channel.fetch(); },
               "cross-relay same-ID conflict");
  first.finish();
  second.finish();
}

void test_rejection_duplicate_and_missing_eose_are_reported() {
  const auto signing_secret = secret(3);
  const SignedNostrEvent event = make_event(signing_secret, "responses");
  OneShotRelay rejected([&](websocket::stream<tcp::socket>& ws) {
    (void)read_json(ws);
    write_json(ws, json::array(
                       {"OK", to_hex(event.id), false, "blocked"}));
  });
  NostrAnchorChannel rejected_channel({rejected.url()}, signing_secret);
  const AnchorPublishResult rejection = rejected_channel.publish(event);
  expect(rejection.accepted_count() == 0 &&
             rejection.endpoints[0].status == AnchorPublishStatus::Rejected,
         "OK=false is an explicit relay rejection, not an ACK");
  rejected.finish();

  OneShotRelay duplicate([&](websocket::stream<tcp::socket>& ws) {
    (void)read_json(ws);
    write_json(ws, json::array(
                       {"OK", to_hex(event.id), true,
                        "duplicate: already saved"}));
  });
  NostrAnchorChannel duplicate_channel({duplicate.url()}, signing_secret);
  const AnchorPublishResult duplicate_result =
      duplicate_channel.publish(event);
  expect(duplicate_result.accepted_count() == 1 &&
             duplicate_result.endpoints[0].status ==
                 AnchorPublishStatus::AlreadyPresent,
         "an idempotent duplicate ACK counts toward W");
  duplicate.finish();

  OneShotRelay no_eose([&](websocket::stream<tcp::socket>& ws) {
    (void)read_json(ws);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  });
  NostrAnchorChannelOptions options;
  options.operation_timeout = std::chrono::seconds(1);
  NostrAnchorChannel timeout_channel(
      {no_eose.url()}, signing_secret, options);
  const AnchorFetchResult timed_out = timeout_channel.fetch();
  expect(timed_out.synchronized_count() == 0 &&
             timed_out.endpoints[0].status ==
                 AnchorFetchStatus::Timeout,
         "a subscription without EOSE never counts toward R");
  no_eose.finish();
}
void test_relay_selection() {
  const std::vector<std::string> candidates = {"slow", "fast", "middle", "down", "fast", "last"};
  auto probe = [](const std::string& endpoint) {
    if (endpoint == "down") throw std::runtime_error("unreachable");
    return AnchorFetchEndpointResult{
        endpoint, AnchorFetchStatus::Synchronized, "",
        endpoint == "fast" ? 1u : endpoint == "middle" ? 2u :
        endpoint == "slow" ? 3u : 4u};
  };
  expect(select_init_relays(candidates, probe) ==
             std::vector<std::string>({"fast", "middle", "slow"}),
         "selection excludes failures, deduplicates, and ranks by latency");
  expect_throw([&] { select_init_relays({"fast", "fast", "middle", "down"}, probe); },
               "selection requires three distinct responsive relays");
  expect_throw([&] { select_init_relays({}, probe); }, "empty candidates");
  expect_throw([&] {
    select_init_relays({"a", "b", "c"}, [](const std::string& endpoint) {
      return AnchorFetchEndpointResult{endpoint, AnchorFetchStatus::Rejected, "closed", 0};
    });
  }, "rejected subscriptions do not qualify");
  const auto tied = select_init_relays({"c", "b", "a", "d"}, [](const std::string& endpoint) {
    return AnchorFetchEndpointResult{endpoint, AnchorFetchStatus::Synchronized, "", 1};
  });
  expect(tied == std::vector<std::string>({"a", "b", "c"}),
         "latency ties have deterministic URL order");
}
}  // namespace

int main() {
  test_relay_selection();
  test_publish_waits_for_matching_ok();
  test_fetch_uses_filter_deduplicates_and_waits_for_eose();
  test_nip42_auth_challenge_is_signed_then_operation_retried();
  test_same_id_with_different_bytes_across_relays_is_rejected();
  test_rejection_duplicate_and_missing_eose_are_reported();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "all Nostr anchor channel tests passed\n";
  return 0;
}
