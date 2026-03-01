#include <fstream>

#include "vault.h"
#include "object_store.h"
#include "vault_engine.h"
#include "util.h"
#include "format.h"
#include "LoginHandler/DropboxLoginHandler.h"


namespace {
    const std::string APP_KEY = "iopaczar4klxa1i";

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

    std::string getTokenPath() {
		return getHomeDirectory() + "/.gitvault/.gitvault_refresh_token";
	}

    void removeRefreshToken() {
        namespace fs = std::filesystem;
        fs::path tokenPath = getTokenPath();

        if (!fs::exists(tokenPath)) {
            throw std::runtime_error("Already logged out.");
            return;
        }

        std::error_code ec;
        fs::remove(tokenPath, ec);
        if (ec) {
            throw std::runtime_error("Failed to remove refresh token file");
        }
    }

	void saveRefreshToken(const std::string& token) {
		namespace fs = std::filesystem;

		fs::path tokenPath = getTokenPath();
		fs::path dir = tokenPath.parent_path();

		// 디렉터리 없으면 생성
		if (!fs::exists(dir)) {
			fs::create_directories(dir);
		}

		std::ofstream ofs(getTokenPath(), std::ios::trunc);
		if (!ofs.is_open()) {
			std::cerr << "Failed to open token file: " << getTokenPath() << "\n";
		}

		ofs << token;
	}

	std::string loadRefreshToken() {
		std::ifstream ifs(getTokenPath());
		if (!ifs.is_open()) return "";
		std::string token;
		std::getline(ifs, token);
		return token;
	}

    void print_usage() {
        std::cout << "gitvault <command> [args] [--password <pw>]\n";
        std::cout << "\nCommands:\n";
        std::cout << "  init <vault_name>\n";
        std::cout << "  lock <vault_name> <plain_dir>\n";
        std::cout << "  add <vault_name> <local_path> <cloud_path>\n";
        std::cout << "  remove <vault_name> <cloud_path>\n";
        std::cout << "  list <vault_name> [path]\n";
        std::cout << "  tree <vault_name> [path]\n";
        std::cout << "  cat <vault_name> <path>\n";
        std::cout << "  quick-scan <vault_name>\n";
        std::cout << "  deep-scan <vault_name>\n";
        std::cout << "\nvault_name can be my_vault or /my_vault.\n";
    }
}

Vault::Vault() {
    lh = new DropboxLoginHandler(APP_KEY);
}

Vault::~Vault() {
    delete lh;
}

void Vault::execute(Command& cmd) {
    if (cmd.command == "help") {
        print_usage();
        return;
    } else if (cmd.command == "login") {
        if (loadRefreshToken() != "") {
            throw std::runtime_error("Already logged in");
        }
        std::string refreshToken = lh->getRefreshToken();
        saveRefreshToken(refreshToken);
        std::cout << "Login finished. Token is saved on your local." << std::endl;

        std::cout << "=============================================" << std::endl;
        print_usage();
        return;
    } else if (cmd.command == "logout") {
        removeRefreshToken();      
        std::cout << "Logged out.\n";
        return;
    }

    // refresh token으로 accesstoken 획득, 실패 시 예외 던짐
    const std::string dropbox_token = lh->login(loadRefreshToken());
    ObjectStore obj_store;

    if (cmd.command == "init") {
        if (cmd.positional.size() != 1) {
            throw std::runtime_error("init requires <vault_name>");
        }
        obj_store.init(dropbox_token, normalize_vault_name(cmd.positional[0]));
        VaultEngine vault_engine(obj_store, read_password(cmd));
        std::cout << "initializing store at " << obj_store.root() << "...\n";
        auto commit_hash = vault_engine.init_vault();
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "lock") {
        if (cmd.positional.size() != 2) {
            throw std::runtime_error("lock requires <vault_name> <plain_dir>");
        }
        obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
        VaultEngine vault_engine(obj_store, read_password(cmd));
        std::filesystem::path plain_dir = cmd.positional[1];
        auto commit_hash = vault_engine.lock_vault(plain_dir);
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "add") {
        if (cmd.positional.size() != 3) {
            throw std::runtime_error("add requires <vault_name> <local_path> <cloud_path>");
        }
        obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
        VaultEngine vault_engine(obj_store, read_password(cmd));
        auto commit_hash = vault_engine.add(std::filesystem::path(cmd.positional[1]), cmd.positional[2]);
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "remove") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("remove requires <vault_name> <cloud_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto commit_hash = vault_engine.remove(cmd.positional[1]);
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "list") {
      if (cmd.positional.size() < 1 || cmd.positional.size() > 2) {
        throw std::runtime_error("list requires <vault_name> [path]");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      std::string path = (cmd.positional.size() == 2) ? cmd.positional[1] : "";
      Tree tree = vault_engine.list_directory(path);
      for (const auto& entry : tree.entries) {
        char type = (entry.type == 1) ? 'd' : 'f';
        std::cout << type << " " << entry.name;
        if (entry.size.has_value()) {
          std::cout << " " << entry.size.value();
        }
        if (entry.mtime.has_value()) {
          std::cout << " " << entry.mtime.value();
        }
        std::cout << "\n";
      }
    } else if (cmd.command == "tree") {
      if (cmd.positional.size() < 1 || cmd.positional.size() > 2) {
        throw std::runtime_error("tree requires <vault_name> [path]");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      std::string path = (cmd.positional.size() == 2) ? cmd.positional[1] : "";
      vault_engine.print_tree(path, std::cout);
    } else if (cmd.command == "cat") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("cat requires <vault_name> <path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      ByteVec data = vault_engine.read_file_from_vault(cmd.positional[1]);
      if (!data.empty()) {
        std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
      }
    } else if (cmd.command == "quick-scan" || cmd.command == "deep-scan") {
      if (cmd.positional.size() != 1) {
        throw std::runtime_error(cmd.command + " requires <vault_name>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      ScanStats stats = (cmd.command == "quick-scan")
                            ? vault_engine.quick_scan()
                            : vault_engine.deep_scan();
      std::cout << "trees=" << stats.trees_checked << " blobs=" << stats.blobs_checked
                << " missing=" << stats.blobs_missing << " hashed=" << stats.blobs_hashed
                << "\n";
    } else {
        print_usage();
    }

    return;
}