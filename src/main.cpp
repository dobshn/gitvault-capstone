#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "vault.h"
#include "util.h"

namespace {
    Command parse_options(int argc, char** argv, int start) {
        Command cmd;

        cmd.command = argv[start];
        for (int i = start + 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--password") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("--password requires a value");
                }
                cmd.password = argv[++i];
            } else if (arg == "--hard") {
                if (cmd.hard) {
                    throw std::runtime_error("--hard may only be specified once");
                }
                cmd.hard = true;
            } else if (arg == "--relay") {
                if (i + 1 >= argc) {
                    throw std::runtime_error("--relay requires a value");
                }
                cmd.relays.push_back(argv[++i]);
            } else {
                cmd.positional.push_back(arg);
            }
        }
        return cmd;
    }

    std::string read_password(const Command& cmd) {
        if (cmd.password.has_value()) {
            return cmd.password.value();
        }
        std::string password;
        std::cerr << "Password: ";
        std::getline(std::cin, password);
        return password;
    }

    std::string normalize_vault_name(std::string vault_name) {
        if (vault_name.empty()) {
            throw std::runtime_error("vault_name required");
        }
        while (vault_name.size() > 1 && vault_name.back() == '/') {
            vault_name.pop_back();
        }
        if (!vault_name.empty() && vault_name.front() == '/') {
            vault_name.erase(vault_name.begin());
        }
        if (vault_name.empty() || vault_name.find('/') != std::string::npos ||
            vault_name.find('\\') != std::string::npos) {
            throw std::runtime_error("vault_name must not contain '/' or '\\\\'");
        }
        return vault_name;
    }
}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage();
            return 1;
        }
        Command cmd = parse_options(argc, argv, 1);

        Vault vault;
        vault.execute(cmd);

    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
}
