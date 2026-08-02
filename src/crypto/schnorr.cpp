#include "crypto/schnorr.h"

#include <stdexcept>

#include <openssl/crypto.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "util.h"

namespace {
class Secp256k1Context {
public:
  Secp256k1Context() : context_(secp256k1_context_create(SECP256K1_CONTEXT_NONE)) {
    if (context_ == nullptr) {
      throw std::runtime_error("failed to create secp256k1 context");
    }
    const ByteVec seed = random_bytes(32);
    if (secp256k1_context_randomize(context_, seed.data()) != 1) {
      secp256k1_context_destroy(context_);
      context_ = nullptr;
      throw std::runtime_error("failed to randomize secp256k1 context");
    }
  }

  ~Secp256k1Context() {
    if (context_ != nullptr) {
      secp256k1_context_destroy(context_);
    }
  }

  Secp256k1Context(const Secp256k1Context&) = delete;
  Secp256k1Context& operator=(const Secp256k1Context&) = delete;

  secp256k1_context* get() const { return context_; }

private:
  secp256k1_context* context_;
};

struct KeypairGuard {
  secp256k1_keypair keypair{};

  ~KeypairGuard() { OPENSSL_cleanse(&keypair, sizeof(keypair)); }

  KeypairGuard() = default;
  KeypairGuard(const KeypairGuard&) = delete;
  KeypairGuard& operator=(const KeypairGuard&) = delete;
};

Secp256k1Context& secp_context() {
  thread_local Secp256k1Context context;
  return context;
}

void initialize_keypair(const std::array<uint8_t, 32>& signing_secret,
                        KeypairGuard& keypair) {
  if (secp256k1_keypair_create(secp_context().get(), &keypair.keypair,
                               signing_secret.data()) != 1) {
    throw std::runtime_error("invalid secp256k1 signing secret");
  }
}

SchnorrPublicKey serialize_public_key(const secp256k1_keypair& keypair) {
  secp256k1_xonly_pubkey xonly_public_key;
  if (secp256k1_keypair_xonly_pub(secp_context().get(), &xonly_public_key,
                                  nullptr, &keypair) != 1) {
    throw std::runtime_error("failed to derive Schnorr public key");
  }

  SchnorrPublicKey serialized{};
  if (secp256k1_xonly_pubkey_serialize(secp_context().get(), serialized.data(),
                                       &xonly_public_key) != 1) {
    throw std::runtime_error("failed to serialize Schnorr public key");
  }
  return serialized;
}
}  // namespace

SchnorrPublicKey schnorr_public_key(
    const std::array<uint8_t, 32>& signing_secret) {
  KeypairGuard keypair;
  initialize_keypair(signing_secret, keypair);
  return serialize_public_key(keypair.keypair);
}

SchnorrSignature schnorr_sign_digest(
    const std::array<uint8_t, 32>& signing_secret,
    const std::array<uint8_t, 32>& digest,
    const std::array<uint8_t, 32>& auxiliary_randomness) {
  KeypairGuard keypair;
  initialize_keypair(signing_secret, keypair);
  SchnorrSignature signature{};
  if (secp256k1_schnorrsig_sign32(secp_context().get(), signature.data(),
                                  digest.data(), &keypair.keypair,
                                  auxiliary_randomness.data()) != 1) {
    throw std::runtime_error("failed to create Schnorr signature");
  }

  const SchnorrPublicKey public_key = serialize_public_key(keypair.keypair);
  if (!schnorr_verify_digest(public_key, digest, signature)) {
    throw std::runtime_error("Schnorr signature self-verification failed");
  }
  return signature;
}

bool schnorr_verify_digest(
    const SchnorrPublicKey& public_key,
    const std::array<uint8_t, 32>& digest,
    const SchnorrSignature& signature) {
  secp256k1_xonly_pubkey parsed_public_key;
  if (secp256k1_xonly_pubkey_parse(secp_context().get(), &parsed_public_key,
                                   public_key.data()) != 1) {
    return false;
  }
  return secp256k1_schnorrsig_verify(
             secp_context().get(), signature.data(), digest.data(), digest.size(),
             &parsed_public_key) == 1;
}
