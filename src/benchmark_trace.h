#pragma once

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string_view>

inline bool gitvault_benchmark_trace_enabled() {
  const char* value = std::getenv("GITVAULT_BENCHMARK_TRACE");
  return value != nullptr && value[0] != '\0' && value[0] != '0';
}

inline void gitvault_benchmark_trace(
    std::string_view phase,
    const std::chrono::steady_clock::time_point& started) {
  if (!gitvault_benchmark_trace_enabled()) return;
  const double milliseconds = std::chrono::duration<double, std::milli>(
      std::chrono::steady_clock::now() - started).count();
  static std::mutex output_mutex;
  std::lock_guard<std::mutex> lock(output_mutex);
  std::cerr << "GITVAULT_BENCH phase=" << phase << " ms="
            << std::fixed << std::setprecision(3) << milliseconds << '\n';
}
