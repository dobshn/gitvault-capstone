#include "dropbox_retry.h"

#include <iostream>
#include <string>

namespace {
int failures = 0;

void expect_equal(int actual, int expected, const std::string& message) {
  if (actual == expected) return;
  std::cerr << "FAIL: " << message << ": expected " << expected
            << ", got " << actual << "\n";
  ++failures;
}

void test_header_takes_precedence() {
  expect_equal(
      dropbox_retry_delay_seconds(
          "7", R"({"error":{"retry_after":3}})", 1),
      7, "Retry-After header takes precedence over JSON body");
}

void test_json_body_fallback() {
  expect_equal(
      dropbox_retry_delay_seconds(
          "", R"({"error":{"reason":{".tag":"too_many_write_operations"},"retry_after":5}})", 1),
      5, "Dropbox JSON retry_after is used when the header is absent");
}

void test_exponential_fallback() {
  expect_equal(dropbox_retry_delay_seconds("", "not-json", 1), 1,
               "first fallback delay");
  expect_equal(dropbox_retry_delay_seconds("", "{}", 2), 2,
               "second fallback delay");
  expect_equal(dropbox_retry_delay_seconds("invalid", "{}", 4), 8,
               "fourth fallback delay");
}

void test_server_delay_does_not_shorten_backoff() {
  expect_equal(
      dropbox_retry_delay_seconds(
          "", R"({"error":{"retry_after":1}})", 4),
      8, "short server delay does not shorten accumulated backoff");
  expect_equal(
      dropbox_retry_delay_seconds(
          "0", R"({"error":{"retry_after":20}})", 1),
      1, "valid header takes precedence and zero still pauses briefly");
}
}  // namespace

int main() {
  test_header_takes_precedence();
  test_json_body_fallback();
  test_exponential_fallback();
  test_server_delay_does_not_shorten_backoff();
  if (failures != 0) return 1;
  std::cout << "all Dropbox retry tests passed\n";
  return 0;
}
