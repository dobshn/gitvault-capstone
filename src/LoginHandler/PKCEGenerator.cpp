#include "PKCEGenerator.h"
#include <random>
#include <algorithm>
#include <stdexcept>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


PKCEGenerator::PKCEGenerator() {
	codeVerifier = generateVerifier();
	codeChallenge = generateChallenge(codeVerifier);
}

PKCEGenerator::PKCEGenerator(size_t verifierLength) {
	if (verifierLength < 43 || verifierLength > 128) {
		throw std::invalid_argument("Verifier length must be between 43 and 128");
	}

	codeVerifier = generateVerifier(verifierLength);
	codeChallenge = generateChallenge(codeVerifier);
}

const std::string& PKCEGenerator::getCodeVerifier() const {
	return codeVerifier;
}

const std::string& PKCEGenerator::getCodeChallenge() const {
	return codeChallenge;
}

std::string PKCEGenerator::generateVerifier(size_t length) {
	const std::string charset =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		"-._~";
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, charset.size() - 1);
	std::string verifier;
	for (size_t i = 0; i < length; ++i) {
		verifier += charset[dis(gen)];
	}
	return verifier;
}

std::string PKCEGenerator::sha256Base64Url(const std::string& input) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
	BIO* bio = BIO_new(BIO_s_mem());
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_push(b64, bio);
	BIO_write(bio, hash, SHA256_DIGEST_LENGTH);
	BIO_flush(bio);
	BUF_MEM* bufferPtr;
	BIO_get_mem_ptr(bio, &bufferPtr);
	std::string b64str(bufferPtr->data, bufferPtr->length);
	BIO_free_all(bio);
	// URL-safe 변환
	for (auto& c : b64str) {
		if (c == '+') c = '-';
		else if (c == '/') c = '_';
	}
	// 패딩 제거
	b64str.erase(std::remove(b64str.begin(), b64str.end(), '='), b64str.end());
	return b64str;
}

std::string PKCEGenerator::generateChallenge(const std::string& verifier) {
	return sha256Base64Url(verifier);
}
