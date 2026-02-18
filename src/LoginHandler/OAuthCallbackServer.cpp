#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../httplib.h"
#endif

#include "OAuthCallbackServer.h"

#include <iostream>
#include <string>


OAuthCallbackServer::OAuthCallbackServer() {
	server.Get("/callback", [&](const httplib::Request& req, httplib::Response& res) {
		if (req.has_param("code")) {
			auth_code = req.get_param_value("code");
			res.set_content("Authorization complete. You may close this window.", "text/plain");
			std::cout << "[+] Authorization code received\n";
		}
		else {
			res.set_content("No code received", "text/plain");
		}});
}

std::string OAuthCallbackServer::start() {
	// 사용 가능한 포트를 8080~8100 사이에서 탐색
	for (int port = 8080; port < 8100; ++port) {
		if (server.bind_to_port("127.0.0.1", port)) {
			this->port = port;
			break;
		}
		// bind_to_port 실패 시 decommission 상태를 해제해야 다음 포트를 시도할 수 있음
		server.stop();
	}

	if (port <= 0) {throw std::runtime_error("Failed to bind OAuth callback server");}

	server_thread = std::thread([&]() { server.listen_after_bind(); });
	std::cout << "Server started on " << port << "\n";

	return "http://127.0.0.1:" + std::to_string(port) + "/callback";
}

void OAuthCallbackServer::stop() {
	server.stop();
	server_thread.join();
	std::cout << "Server stopped on " << port << "\n";
}

std::string OAuthCallbackServer::waitForAuthorizationCode() {
	while (auth_code.empty()) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	return auth_code;
}

