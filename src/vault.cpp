#include <fstream>
#include <iostream>
#include <iomanip>
#include <cctype>

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
        if (cmd.positional.size() != 1 && cmd.positional.size() != 2) {
            throw std::runtime_error("init requires <vault_name> [folder_path]");
        }
        std::string vault_name = normalize_vault_name(cmd.positional[0]);
        std::filesystem::path local_vault_dir = getHomeDirectory() + ".gitvault/" + vault_name;
        if (std::filesystem::exists(local_vault_dir)) {
            std::error_code ec;
            std::filesystem::remove_all(local_vault_dir, ec);
        }
        obj_store.init(dropbox_token, vault_name);
        VaultEngine vault_engine(obj_store, read_password(cmd));
        std::cout << "initializing store at " << obj_store.root() << "...\n";
        auto commit_hash = vault_engine.init_vault();
        if (cmd.positional.size() == 2) {
          std::filesystem::path plain_dir = cmd.positional[1];
          commit_hash = vault_engine.lock_vault(plain_dir);
        }
        std::cout << "\ncommit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "add") {
        if (cmd.positional.size() != 3) {
            throw std::runtime_error("add requires <vault_name> <local_path> <cloud_path>");
        }
        obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
        VaultEngine vault_engine(obj_store, read_password(cmd));
        auto commit_hash = vault_engine.add(std::filesystem::path(cmd.positional[1]), cmd.positional[2]);
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "mkdir") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("mkdir requires <vault_name> <cloud_dir_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto commit_hash = vault_engine.mkdir(cmd.positional[1]);
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "remove") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("remove requires <vault_name> <cloud_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto commit_hash = vault_engine.remove(cmd.positional[1]);
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "rmdir") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("rmdir requires <vault_name> <cloud_dir_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      const std::string cloud_dir_path = cmd.positional[1];

      try {
        auto commit_hash = vault_engine.rmdir(cloud_dir_path, false);
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
      } catch (const std::runtime_error& ex) {
        const std::string message = ex.what();
        const std::string not_empty_prefix = "directory not empty:";
        if (message.rfind(not_empty_prefix, 0) != 0) {
          throw;
        }

        std::cout << "warning: directory '" << cloud_dir_path << "' is not empty.\n";
        std::cout << "Delete recursively? [y/N]: ";
        std::string answer;
        std::getline(std::cin, answer);
        if (answer!="y") {
          std::cout << "aborted.\n";
          return;
        }

        auto commit_hash = vault_engine.rmdir(cloud_dir_path, true);
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
      }
    } else if (cmd.command == "list") {
      if (cmd.positional.size() < 1 || cmd.positional.size() > 2) {
        throw std::runtime_error("list requires <vault_name> [path]");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      std::string path = (cmd.positional.size() == 2) ? cmd.positional[1] : "";
      Tree tree = vault_engine.list_directory(path);

      std::cout << std::left
                << std::setw(25) << "NAME"
                << std::setw(12) << "SIZE"
                << "Modification Time\n";
      std::cout << std::string(57, '-') << "\n";
      for (const auto& entry : tree.entries) {
        std::string name = entry.name;
        if (entry.type == 1) { // 디렉터리인 경우 / 붙이기. type=1 은 tree를 의미.
          name += "/";
        }
        std::cout << std::left
                  << std::setw(25) << name;
        if (entry.size.has_value())
          std::cout << std::setw(12) << entry.size.value();
        else
          std::cout << std::setw(12) << "-";
        if (entry.mtime.has_value()) {
          std::time_t t = entry.mtime.value();
          std::tm* tm = std::localtime(&t);
          char buf[20];
          std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", tm);
          std::cout << buf;
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
    } else if (cmd.command == "sync") {
      if (cmd.positional.size() != 1) {
        throw std::runtime_error(cmd.command + " requires <vault_name>");
      }
      std::cout <<
      "Warning: 'sync' will fetch the vault config and HEAD from the cloud.\n"
      "This resets local state and prevents detection of rollback attacks\n"
      "performed on the remote storage.\n"
      "Confidentiality and integrity will still be preserved.\n\n"
      "Proceed? (y/N): ";

      std::string answer;
      std::getline(std::cin, answer);
      if (!(answer == "y" || answer == "Y")) {
        std::cout << "Sync cancelled.\n";
        return;
      }

      std::string vault_name = normalize_vault_name(cmd.positional[0]);
      std::filesystem::path local_vault_dir = getHomeDirectory() + ".gitvault/" + vault_name;
      if (std::filesystem::exists(local_vault_dir)) {
          std::error_code ec;
          std::filesystem::remove_all(local_vault_dir, ec);
      }
      obj_store.fetch(dropbox_token, vault_name);
      VaultEngine vault_engine(obj_store, read_password(cmd));
      vault_engine.sync();
    } else {
        print_usage();
    }

    return;
}
