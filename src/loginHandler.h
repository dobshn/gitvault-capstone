#pragma once
#include <string>

using string = std::string;

class loginHandler {
public:
	virtual string login(const std::string&) = 0;
	virtual string getRefreshToken() = 0;
    virtual ~loginHandler() = default;
};