#pragma once

#include <string>
#include <vector>
#include <optional>

#include "loginHandler.h"

struct Command {
    std::string command;
    std::optional<std::string> password;
    std::vector<std::string> positional;
};

class Vault {
private:
    loginHandler* lh;
public:
    Vault();
    ~Vault();
    void execute(Command& cmd);
};
