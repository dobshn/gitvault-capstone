#ifndef OAUTH_CALLBACK_SERVER_H
#define OAUTH_CALLBACK_SERVER_H

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include "../httplib.h"
#include <thread>
#include <string>


class OAuthCallbackServer {
private:
	int port;
	std::string auth_code;
	std::thread server_thread;
	httplib::Server server;

public:
	OAuthCallbackServer();
	std::string start();
	std::string waitForAuthorizationCode();
	void stop();
};


#endif // OAUTH_CALLBACK_SERVER_H