#include "vector_clock.h"

#include <limits>
#include <stdexcept>

namespace {
uint64_t component(const VectorClock& clock, const ReplicaId& replica_id) {
  const auto found = clock.find(replica_id);
  return found == clock.end() ? 0 : found->second;
}
}  // namespace

void validate_vector_clock(const VectorClock& clock) {
  if (clock.size() > kMaximumVectorClockEntries) {
    throw std::runtime_error("vector clock component limit exceeded");
  }
  for (const auto& [replica_id, counter] : clock) {
    (void)replica_id;
    if (counter == 0) {
      throw std::runtime_error(
          "vector clock must omit zero-valued components");
    }
  }
}

VectorClockRelation compare_vector_clocks(const VectorClock& left,
                                          const VectorClock& right) {
  validate_vector_clock(left);
  validate_vector_clock(right);
  bool left_less = false;
  bool right_less = false;

  for (const auto& [replica_id, left_value] : left) {
    const uint64_t right_value = component(right, replica_id);
    left_less = left_less || left_value < right_value;
    right_less = right_less || right_value < left_value;
  }
  for (const auto& [replica_id, right_value] : right) {
    if (left.count(replica_id) != 0) continue;
    left_less = left_less || right_value != 0;
  }

  if (left_less && right_less) return VectorClockRelation::Concurrent;
  if (left_less) return VectorClockRelation::Before;
  if (right_less) return VectorClockRelation::After;
  return VectorClockRelation::Equal;
}

VectorClock increment_vector_clock(const VectorClock& clock,
                                   const ReplicaId& replica_id) {
  validate_vector_clock(clock);
  VectorClock result = clock;
  uint64_t& counter = result[replica_id];
  if (counter == std::numeric_limits<uint64_t>::max()) {
    throw std::runtime_error("vector clock counter overflow");
  }
  ++counter;
  validate_vector_clock(result);
  return result;
}

const char* vector_clock_relation_name(VectorClockRelation relation) {
  switch (relation) {
    case VectorClockRelation::Equal: return "EQUAL";
    case VectorClockRelation::Before: return "BEFORE";
    case VectorClockRelation::After: return "AFTER";
    case VectorClockRelation::Concurrent: return "CONCURRENT";
  }
  return "UNKNOWN";
}
