#ifndef PKCE_GENERATOR_H
#define PKCE_GENERATOR_H

#include <string>

class PKCEGenerator {
public:
    PKCEGenerator(); // 생성 시 verifier + challenge 생성
    PKCEGenerator(size_t verifierLength); // verifier 길이 지정 가능

    const std::string& getCodeVerifier() const;
    const std::string& getCodeChallenge() const;

private:
    std::string codeVerifier;
    std::string codeChallenge;

    static std::string generateVerifier(size_t length = 64);
    static std::string generateChallenge(const std::string& verifier);

    static std::string sha256Base64Url(const std::string& input);
};

#endif // PKCE_GENERATOR_H
