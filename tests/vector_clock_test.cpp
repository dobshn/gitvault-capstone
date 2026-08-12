#include "vector_clock.h"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
int failures = 0;

template <size_t N>
std::array<uint8_t, N> filled(uint8_t value) {
  std::array<uint8_t, N> result{};
  result.fill(value);
  return result;
}

void expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    ++failures;
  }
}

void test_relations_and_increment() {
  const ReplicaId a = filled<16>(0x0a);
  const ReplicaId b = filled<16>(0x0b);
  const VectorClock empty;
  const VectorClock a1 = increment_vector_clock(empty, a);
  const VectorClock a2 = increment_vector_clock(a1, a);
  const VectorClock b1 = increment_vector_clock(empty, b);
  VectorClock joined = a2;
  joined[b] = 1;

  expect(compare_vector_clocks(empty, empty) == VectorClockRelation::Equal,
         "empty clocks are equal");
  expect(compare_vector_clocks(empty, a1) == VectorClockRelation::Before,
         "a missing component is the implicit zero value");
  expect(compare_vector_clocks(a2, a1) == VectorClockRelation::After,
         "a greater component is causally after");
  expect(compare_vector_clocks(a1, b1) == VectorClockRelation::Concurrent,
         "independently incremented replicas are incompatible");
  expect(compare_vector_clocks(a2, joined) == VectorClockRelation::Before,
         "adding a component advances an existing clock");
}

void test_invalid_and_overflow() {
  const ReplicaId a = filled<16>(0x0a);
  bool zero_rejected = false;
  try {
    validate_vector_clock(VectorClock{{a, 0}});
  } catch (const std::runtime_error&) {
    zero_rejected = true;
  }
  expect(zero_rejected, "zero components must be omitted");

  bool overflow_rejected = false;
  try {
    (void)increment_vector_clock(
        VectorClock{{a, std::numeric_limits<uint64_t>::max()}}, a);
  } catch (const std::runtime_error&) {
    overflow_rejected = true;
  }
  expect(overflow_rejected, "counter overflow fails closed");

  VectorClock maximum;
  for (size_t index = 0; index < kMaximumVectorClockEntries; ++index) {
    ReplicaId replica{};
    replica[14] = static_cast<uint8_t>(index >> 8);
    replica[15] = static_cast<uint8_t>(index);
    maximum.emplace(replica, 1);
  }
  validate_vector_clock(maximum);
  ReplicaId extra{};
  extra[0] = 1;
  bool component_limit_rejected = false;
  try {
    (void)increment_vector_clock(maximum, extra);
  } catch (const std::runtime_error&) {
    component_limit_rejected = true;
  }
  expect(component_limit_rejected,
         "adding a 257th replica component fails closed");
}
}  // namespace

int main() {
  test_relations_and_increment();
  test_invalid_and_overflow();
  if (failures != 0) return 1;
  std::cout << "all vector clock tests passed\n";
  return 0;
}
