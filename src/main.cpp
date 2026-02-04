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

void print_usage() {
  std::cout << "gitvault <command> [args] [--password <pw>] [--password-file <path>] [--state <path>]\n";
  std::cout << "\nCommands:\n";
  std::cout << "  init <store_dir>\n";
  std::cout << "  lock <plain_dir> <store_dir>\n";
  std::cout << "  list <store_dir> [path]\n";
  std::cout << "  tree <store_dir> [path]\n";
  std::cout << "  cat <store_dir> <path>\n";
  std::cout << "  quick-scan <store_dir>\n";
  std::cout << "  deep-scan <store_dir>\n";
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

    if (command == "init") {
      if (opts.positional.size() != 1) {
        throw std::runtime_error("init requires <store_dir>");
      }
      ObjectStore store(opts.positional[0]);
      Config cfg = ensure_store_config(store);
      std::cout << "initialized store at " << store.root().string() << "\n";
      std::cout << "kdf_salt=" << to_hex(cfg.salt) << "\n";
      return 0;
    }

    if (command == "lock") {
      if (opts.positional.size() != 2) {
        throw std::runtime_error("lock requires <plain_dir> <store_dir>");
      }
      std::filesystem::path plain_dir = opts.positional[0];
      ObjectStore store(opts.positional[1]);
      Config cfg = ensure_store_config(store);
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      std::filesystem::path state_path = opts.state_path.value_or(plain_dir / ".gitvault_state");
      auto commit_hash = lock_vault(plain_dir, store, keys, state_path);
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
      std::cout << "state=" << state_path.string() << "\n";
      return 0;
    }

    if (command == "list") {
      if (opts.positional.size() < 1 || opts.positional.size() > 2) {
        throw std::runtime_error("list requires <store_dir> [path]");
      }
      ObjectStore store(opts.positional[0]);
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
        throw std::runtime_error("tree requires <store_dir> [path]");
      }
      ObjectStore store(opts.positional[0]);
      Config cfg = store.load_config();
      std::string password = read_password(opts);
      Keys keys = derive_keys(cfg, password);
      std::string path = (opts.positional.size() == 2) ? opts.positional[1] : "";
      print_tree(store, keys, opts.state_path, path, std::cout);
      return 0;
    }

    if (command == "cat") {
      if (opts.positional.size() != 2) {
        throw std::runtime_error("cat requires <store_dir> <path>");
      }
      ObjectStore store(opts.positional[0]);
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
        throw std::runtime_error(command + " requires <store_dir>");
      }
      ObjectStore store(opts.positional[0]);
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
