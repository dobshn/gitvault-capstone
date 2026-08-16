#include "dropbox_retry.h"

#include "json.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <string>

namespace {
using nlohmann::json;

int parse_nonnegative_seconds(std::string_view value) {
  if (value.empty()) return -1;
  int seconds = 0;
  const char* begin = value.data();
  const char* end = begin + value.size();
  const auto parsed = std::from_chars(begin, end, seconds);
  if (parsed.ec != std::errc{} || parsed.ptr != end || seconds < 0) return -1;
  return seconds;
}

int retry_after_from_body(std::string_view response_body) {
  const json document = json::parse(response_body, nullptr, false);
  if (document.is_discarded() || !document.is_object()) return -1;
  const auto error = document.find("error");
  if (error == document.end() || !error->is_object()) return -1;
  const auto retry_after = error->find("retry_after");
  if (retry_after == error->end() || !retry_after->is_number_integer()) {
    return -1;
  }
  const auto seconds = retry_after->get<long long>();
  if (seconds < 0 || seconds > std::numeric_limits<int>::max()) return -1;
  return static_cast<int>(seconds);
}
}  // namespace

int dropbox_retry_delay_seconds(std::string_view retry_after_header,
                                std::string_view response_body,
                                int attempt) {
  attempt = std::max(attempt, 1);
  const int exponent = std::min(attempt - 1, 5);
  const int fallback_backoff = 1 << exponent;

  int retry_after = parse_nonnegative_seconds(retry_after_header);
  if (retry_after < 0) retry_after = retry_after_from_body(response_body);
  if (retry_after < 1) retry_after = 1;
  return std::max(retry_after, fallback_backoff);
}
