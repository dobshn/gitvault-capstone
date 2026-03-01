#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../httplib.h"
#endif
#include "../json.hpp"
#include "DropboxLoginHandler.h"
#include "OAuthCallbackServer.h"
#include "PKCEGenerator.h"
#include <string>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <filesystem>

using json = nlohmann::json;
using string = std::string;

DropboxLoginHandler::DropboxLoginHandler(const std::string& APPKEY) : APPKEY(APPKEY), callbackServer(), pkce() {}
DropboxLoginHandler::DropboxLoginHandler(const std::string& APPKEY, size_t verifierLength) : APPKEY(APPKEY), callbackServer(), pkce(verifierLength) {}

string DropboxLoginHandler::getRefreshToken() {
	redirect_uri = callbackServer.start(); // 콜백 서버 시작
	std::cout << "[+] uri: " << redirect_uri << std::endl;

	std::string authUrl =
		"https://www.dropbox.com/oauth2/authorize"
		"?response_type=code"
		"&client_id=" + APPKEY +
		"&redirect_uri=" + redirect_uri +
		"&code_challenge=" + pkce.getCodeChallenge() +
		"&code_challenge_method=S256"
		"&token_access_type=offline"; // Dropbox OAuth2 인증 URL 생성
	openBrowser(authUrl); // 기본 브라우저에서 인증 URL 열기 (리눅스 기준)
	authCode = callbackServer.waitForAuthorizationCode(); // 인증 코드 대기
	callbackServer.stop(); // 콜백 서버 중지
	std::cout << "[+] Authorization Code: " << authCode << std::endl; // 인증 코드 출력 (디버깅용)

	// auth code로 refreshToken 요청 
	httplib::SSLClient cli("api.dropboxapi.com", 443);
	cli.set_follow_location(true);

	std::string body =
		"code=" + authCode +
		"&grant_type=authorization_code"
		"&redirect_uri=" + redirect_uri +
		"&client_id=" + APPKEY +
		"&code_verifier=" + pkce.getCodeVerifier();

	auto res = cli.Post(
		"/oauth2/token",
		body,
		"application/x-www-form-urlencoded"
	);

	if (!res) {
		throw std::runtime_error("TLS request failed");
	}
	if (res->status != 200) {
		throw std::runtime_error("Failed to exchange code for token");
	}

	// 응답 JSON 파싱
	auto response_json = json::parse(res->body);
	return response_json["refresh_token"];
}

string DropboxLoginHandler::login(const std::string& token) {
	httplib::SSLClient cli("api.dropboxapi.com", 443);
	cli.set_follow_location(true);
	std::string body =
		"refresh_token=" + token +
		"&grant_type=refresh_token"
		"&client_id=" + APPKEY;
	auto res = cli.Post(
		"/oauth2/token",
		body,
		"application/x-www-form-urlencoded"
	);
	if (!res) {
		throw std::runtime_error("TLS request failed");
	}
	if (res->status != 200) {
		throw std::runtime_error("Failed to get access token. Please \"login\" first.");
	}
	// 응답 JSON 파싱
	auto response_json = json::parse(res->body);
	return response_json["access_token"];
}

// 아래는 클래스 내부에서 사용하는 함수들입니다. 
void DropboxLoginHandler::openBrowser(const std::string& url) {
	#if defined(_WIN32) || defined(_WIN64)
	std::string cmd = "cmd.exe /c start \"\" \"" + url + "\"";
	std::system(cmd.c_str());

	#elif defined(__APPLE__)
	std::string cmd = "open \"" + url + "\"";
	std::system(cmd.c_str());

	#elif defined(__linux__)
	const char* wsl = std::getenv("WSL_DISTRO_NAME");
	if (wsl) {
		std::cout << "[WSL detected] Open this URL manually:\n" << url << std::endl;
	}
	else {
		std::string cmd = "xdg-open \"" + url + "\"";
		if (std::system(cmd.c_str()) != 0) {
			std::cout << "Failed to open browser. Open this URL manually:\n" << url << std::endl;
		}
	}

	#else
	std::cout << "Unsupported OS. Open this URL manually:\n" << url << std::endl;
	#endif
}
