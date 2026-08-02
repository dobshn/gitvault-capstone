#pragma once

#include <array>
#include <cstdint>

using SchnorrPublicKey = std::array<uint8_t, 32>;
using SchnorrSignature = std::array<uint8_t, 64>;

SchnorrPublicKey schnorr_public_key(
    const std::array<uint8_t, 32>& signing_secret);
SchnorrSignature schnorr_sign_digest(
    const std::array<uint8_t, 32>& signing_secret,
    const std::array<uint8_t, 32>& digest,
    const std::array<uint8_t, 32>& auxiliary_randomness);
bool schnorr_verify_digest(
    const SchnorrPublicKey& public_key,
    const std::array<uint8_t, 32>& digest,
    const SchnorrSignature& signature);
