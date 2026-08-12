#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

using ReplicaId = std::array<uint8_t, 16>;
using VectorClock = std::map<ReplicaId, uint64_t>;

constexpr size_t kMaximumVectorClockEntries = 256;

enum class VectorClockRelation {
  Equal,
  Before,
  After,
  Concurrent,
};

VectorClockRelation compare_vector_clocks(const VectorClock& left,
                                          const VectorClock& right);
VectorClock increment_vector_clock(const VectorClock& clock,
                                   const ReplicaId& replica_id);
void validate_vector_clock(const VectorClock& clock);
const char* vector_clock_relation_name(VectorClockRelation relation);
