#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "vault.h"

namespace {
struct Options {
  std::optional<std::string> password;
  std::optional<std::string> password_file;
  std::optional<std::string> dropbox_token;
  std::optional<std::filesystem::path> state_path;
  std::vector<std::string> positional;
};

Options parse_options(int argc, char** argv, int start) {
  Options opts;
  for (int i = start; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--password") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--password requires a value");
      }
      opts.password = argv[++i];
    } else if (arg == "--password-file") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--password-file requires a path");
      }
      opts.password_file = argv[++i];
    } else if (arg == "--state") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--state requires a path");
      }
      opts.state_path = std::filesystem::path(argv[++i]);
    } else if (arg == "--dropbox-token") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--dropbox-token requires a value");
      }
      opts.dropbox_token = argv[++i];
    } else {
      opts.positional.push_back(arg);
    }
  }
  return opts;
}

std::string read_password(const Options& opts) {
  if (opts.password.has_value()) {
    return opts.password.value();
  }
  if (opts.password_file.has_value()) {
    std::ifstream file(opts.password_file.value());
    if (!file) {
      throw std::runtime_error("failed to read password file");
    }
    std::string line;
    std::getline(file, line);
    return line;
  }
  std::string password;
  std::cerr << "Password: ";
  std::getline(std::cin, password);
  return password;
}

std::string read_dropbox_token(const Options& opts) {
  if (opts.dropbox_token.has_value()) {
    return opts.dropbox_token.value();
  }

  const char* token = std::getenv("GITVAULT_DROPBOX_TOKEN");
  if (token != nullptr && token[0] != '\0') {
    return token;
  }

  token = std::getenv("DROPBOX_ACCESS_TOKEN");
  if (token != nullptr && token[0] != '\0') {
    return token;
  }

  throw std::runtime_error(
      "Dropbox token is required. Use --dropbox-token or set GITVAULT_DROPBOX_TOKEN.");
}

void print_usage() {
  std::cout << "gitvault <command> [args] [--dropbox-token <token>] [--password <pw>] "
               "[--password-file <path>] [--state <path>]\n";
  std::cout << "\nCommands:\n";
  std::cout << "  init <store_root>\n";
  std::cout << "  lock <plain_dir> <store_root>\n";
  std::cout << "  add <store_root> <local_path> <cloud_path>\n";
  std::cout << "  list <store_root> [path]\n";
  std::cout << "  tree <store_root> [path]\n";
  std::cout << "  cat <store_root> <path>\n";
  std::cout << "  quick-scan <store_root>\n";
  std::cout << "  deep-scan <store_root>\n";
  std::cout << "\nstore_root is a Dropbox root path like /my_gitvault\n";
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      print_usage();
      return 1;
    }

    std::string command = argv[1];
    Options opts = parse_options(argc, argv, 2);
    const bool needs_store = (command == "init" || command == "lock" || command == "list" ||
                              command == "tree" || command == "cat" || command == "quick-scan" ||
                              command == "add" ||
                              command == "deep-scan");
    const std::string dropbox_token = needs_store ? read_dropbox_token(opts) : "";

    if (command == "init") {
      if (opts.positional.size() != 1) {
        throw std::runtime_error("init requires <store_root>");
      }
      ObjectStore store(dropbox_token, opts.positional[0]);
      Config cfg = ensure_store_config(store);
      std::cout << "initialized store at " << store.root() << "\n";
      std::cout << "kdf_salt=" << to_hex(cfg.salt) << "\n";
      return 0;
    }

    if (command == "lock") {
      if (opts.positional.size() != 2) {
        throw std::runtime_error("lock requires <plain_dir> <store_root>");
      }
      std::filesystem::path plain_dir = opts.positional[0];
      ObjectStore store(dropbox_token, opts.positional[1]);
      Config cfg = ensure_store_config(store);
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      std::filesystem::path state_path = opts.state_path.value_or(plain_dir / ".gitvault_state");
      auto commit_hash = lock_vault(plain_dir, store, keys, state_path);
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
      std::cout << "state=" << state_path.string() << "\n";
      return 0;
    }

    if (command == "add") {
      if (opts.positional.size() != 3) {
        throw std::runtime_error("add requires <store_root> <local_path> <cloud_path>");
      }
      ObjectStore store(dropbox_token, opts.positional[0]);
      Config cfg = store.load_config();
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      auto commit_hash = add(store, keys, std::filesystem::path(opts.positional[1]), opts.positional[2]);
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
      return 0;
    }

    if (command == "list") {
      if (opts.positional.size() < 1 || opts.positional.size() > 2) {
        throw std::runtime_error("list requires <store_root> [path]");
      }
      ObjectStore store(dropbox_token, opts.positional[0]);
      Config cfg = store.load_config();
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      std::string path = (opts.positional.size() == 2) ? opts.positional[1] : "";
      Tree tree = list_directory(store, keys, opts.state_path, path);
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
      return 0;
    }

    if (command == "tree") {
      if (opts.positional.size() < 1 || opts.positional.size() > 2) {
        throw std::runtime_error("tree requires <store_root> [path]");
      }
      ObjectStore store(dropbox_token, opts.positional[0]);
      Config cfg = store.load_config();
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      std::string path = (opts.positional.size() == 2) ? opts.positional[1] : "";
      print_tree(store, keys, opts.state_path, path, std::cout);
      return 0;
    }

    if (command == "cat") {
      if (opts.positional.size() != 2) {
        throw std::runtime_error("cat requires <store_root> <path>");
      }
      ObjectStore store(dropbox_token, opts.positional[0]);
      Config cfg = store.load_config();
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      ByteVec data = read_file_from_vault(store, keys, opts.state_path, opts.positional[1]);
      if (!data.empty()) {
        std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
      }
      return 0;
    }

    if (command == "quick-scan" || command == "deep-scan") {
      if (opts.positional.size() != 1) {
        throw std::runtime_error(command + " requires <store_root>");
      }
      ObjectStore store(dropbox_token, opts.positional[0]);
      Config cfg = store.load_config();
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      ScanStats stats = (command == "quick-scan")
                            ? quick_scan(store, keys, opts.state_path)
                            : deep_scan(store, keys, opts.state_path);
      std::cout << "trees=" << stats.trees_checked << " blobs=" << stats.blobs_checked
                << " missing=" << stats.blobs_missing << " hashed=" << stats.blobs_hashed
                << "\n";
      return 0;
    }

    print_usage();
    return 1;
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << "\n";
    return 1;
  }
}
