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
std::array<uint8_t, 32> secp256k1_shared_x(
    const std::array<uint8_t, 32>& private_key,
    const SchnorrPublicKey& public_key);
