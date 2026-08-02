#pragma once

#include <cstddef>

#include "util.h"

ByteVec hkdf_extract_sha256(const ByteVec& input_key_material,
                            const ByteVec& salt);
ByteVec hkdf_expand_sha256(const ByteVec& pseudorandom_key,
                           const ByteVec& info,
                           size_t output_length);

ByteVec hkdf_sha256(const ByteVec& input_key_material,
                    const ByteVec& salt,
                    const ByteVec& info,
                    size_t output_length);
