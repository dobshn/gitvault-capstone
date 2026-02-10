#pragma once
#include "../loginHandler.h"
#include "OAuthCallbackServer.h"
#include "PKCEGenerator.h"
#include <string>

using string = std::string;

class DropboxLoginHandler : public loginHandler {
private:
	const string APPKEY;
	string redirect_uri;
	std::string authCode;

	OAuthCallbackServer callbackServer;
	PKCEGenerator pkce;

	// 브라우저 여는 함수
	void openBrowser(const std::string& url);

public:
	DropboxLoginHandler(const std::string& APPKEY);
	DropboxLoginHandler(const std::string& APPKEY, size_t verifierLength);
	string login(const std::string&) override;
	string getRefreshToken() override;
};