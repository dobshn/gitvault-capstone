#pragma once

#include <array>

#include "crypto/sha256.h"
#include "util.h"

std::array<uint8_t, 32> hmac_sha256(const ByteVec& key, const ByteVec& data);
