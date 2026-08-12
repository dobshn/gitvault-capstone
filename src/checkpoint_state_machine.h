#pragma once

#include "anchor_state_machine.h"
#include "anchor_trust_store.h"

struct CheckpointStateInput {
  std::vector<SignedNostrEvent> witness_events;
  AnchorCheckpoint local_checkpoint;
  VaultHeadState local_head;
  VaultHeadState cloud_head;
  AnchorHash cloud_head_envelope_hash{};
  bool channel_synchronized = true;
  bool read_only_operation = false;
  bool prepared_write_exists = false;
};

AnchorStateResult evaluate_checkpoint_state(
    const AnchorStateContext& context,
    const CheckpointStateInput& input);

