#pragma once

#include <string>

#include "util.h"

ByteVec pbkdf2_hmac_sha256(const std::string& password,
                           const ByteVec& salt,
                           uint32_t iterations,
                           size_t dk_len);
