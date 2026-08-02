#include "anchor_channel.h"

#include <algorithm>

size_t AnchorPublishResult::accepted_count() const {
  return static_cast<size_t>(std::count_if(
      endpoints.begin(), endpoints.end(), [](const AnchorPublishReceipt& item) {
        return item.status == AnchorPublishStatus::Accepted ||
               item.status == AnchorPublishStatus::AlreadyPresent;
      }));
}

size_t AnchorFetchResult::synchronized_count() const {
  return static_cast<size_t>(std::count_if(
      endpoints.begin(), endpoints.end(),
      [](const AnchorFetchEndpointResult& item) {
        return item.status == AnchorFetchStatus::Synchronized;
      }));
}
