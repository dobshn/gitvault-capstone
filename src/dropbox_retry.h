#pragma once

#include <string_view>

constexpr int kDropboxUploadMaxAttempts = 5;

// Returns a delay in seconds for the next attempt. Retry-After headers take
// precedence over Dropbox's JSON retry_after field. If neither is usable, an
// exponential backoff based on the one-indexed attempt number is returned.
int dropbox_retry_delay_seconds(std::string_view retry_after_header,
                                std::string_view response_body,
                                int attempt);
