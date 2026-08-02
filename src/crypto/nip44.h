#pragma once

#include <array>
#include <string>

#include "crypto/schnorr.h"

using Nip44ConversationKey = std::array<uint8_t, 32>;

Nip44ConversationKey nip44_conversation_key(
    const std::array<uint8_t, 32>& private_key,
    const SchnorrPublicKey& public_key);

std::string nip44_encrypt(
    const std::string& plaintext,
    const Nip44ConversationKey& conversation_key);
std::string nip44_encrypt_with_nonce(
    const std::string& plaintext,
    const Nip44ConversationKey& conversation_key,
    const std::array<uint8_t, 32>& nonce);
std::string nip44_decrypt(
    const std::string& payload,
    const Nip44ConversationKey& conversation_key);
