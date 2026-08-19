#include <fstream>
#include <iostream>
#include <iomanip>
#include <cctype>
#include <sstream>

#include "vault.h"
#include "object_store.h"
#include "vault_engine.h"
#include "util.h"
#include "format.h"
#include "anchor_coordinator.h"
#include "anchor_trust_store.h"
#include "nostr_anchor_channel.h"
#include "client_bootstrap.h"
#include "crypto/CryptoImpl.h"
#include "crypto/sha256.h"
#include "vault_identity.h"
#include "LoginHandler/DropboxLoginHandler.h"


namespace {
    const std::string APP_KEY = "iopaczar4klxa1i";

    std::string read_password(const Command& cmd) {
        if (cmd.password.has_value()) {
            return cmd.password.value();
        }
        std::string password;
        while (true) {
          std::cerr << "Password: ";
          std::getline(std::cin, password);
          if (!password.empty()) {
              return password;
          }
          std::cerr << "Password cannot be empty. Please try again.\n";
        }
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

    std::unique_ptr<AnchorCoordinator> make_anchor_coordinator(
        ObjectStore& store,
        VaultEngine& engine) {
      AnchorTrustStore trust(store.trust_directory(), engine.trust_mac_key());
      if (!trust.channel_exists()) {
        throw std::runtime_error(
            "anchor channel is not configured for this vault");
      }
      const AnchorChannelConfig config = trust.load_channel();
      auto channel = std::make_unique<NostrAnchorChannel>(
          config.relay_urls, engine.identity().signing_secret);
      return std::make_unique<AnchorCoordinator>(
          store, engine, std::move(channel));
    }

    std::string format_vector_clock(const VectorClock& clock) {
      std::ostringstream output;
      output << '{';
      bool first = true;
      for (const auto& [replica, counter] : clock) {
        if (!first) output << ',';
        first = false;
        output << to_hex(ByteVec(replica.begin(), replica.end())) << ':'
               << counter;
      }
      output << '}';
      return output.str();
    }

    const char* fetch_status_name(AnchorFetchStatus status) {
      switch (status) {
        case AnchorFetchStatus::Synchronized: return "EOSE";
        case AnchorFetchStatus::Rejected: return "REJECTED";
        case AnchorFetchStatus::Timeout: return "TIMEOUT";
        case AnchorFetchStatus::TransportError: return "TRANSPORT_ERROR";
      }
      return "UNKNOWN";
    }

    void print_anchor_status(const AnchorCoordinatorStatus& status) {
      std::cout << "L=" << to_hex(status.local_head) << "\n"
                << "C=" << to_hex(status.cloud_head) << "\n"
                << "N=";
      if (status.observed_head.has_value()) {
        std::cout << to_hex(*status.observed_head);
      } else {
        std::cout << "unavailable";
      }
      std::cout << "\n"
                << "clock_L="
                << format_vector_clock(status.local_head_state.clock) << "\n"
                << "clock_C="
                << format_vector_clock(status.cloud_head_state.clock) << "\n"
                << "clock_N="
                << format_vector_clock(status.decision.verified_clock) << "\n"
                << "relation_L_C=" << status.local_cloud_relation << "\n"
                << "relation_C_N=" << status.cloud_observed_relation << "\n"
                << "relation_L_N=" << status.local_observed_relation << "\n"
                << "cloud_revision=" << status.cloud_revision << "\n"
                << "state="
                << anchor_client_state_name(status.decision.state) << "\n"
                << "reason="
                << anchor_state_reason_name(status.decision.reason) << "\n"
                << "action="
                << anchor_state_action_name(status.decision.action) << "\n"
                << "detail=" << status.decision.detail << "\n";
      for (const auto& relay : status.relay_fetch.endpoints) {
        std::cout << "relay=" << relay.endpoint << " "
                  << fetch_status_name(relay.status)
                  << " latency_ms=" << relay.latency_milliseconds;
        if (!relay.message.empty()) std::cout << " " << relay.message;
        std::cout << "\n";
      }
      if (status.prepared.has_value()) {
        std::cout << "pending_operation="
                  << to_hex(ByteVec(status.prepared->operation_id.begin(),
                                    status.prepared->operation_id.end()))
                  << " phase="
                  << prepared_write_phase_name(status.prepared->phase)
                  << "\n";
      } else {
        std::cout << "pending_operation=none\n";
      }
      for (const auto& outbox : status.pending_outbox) {
        for (const auto& relay : status.relay_fetch.endpoints) {
          std::cout << "outbox=" << to_hex(outbox.event.id)
                    << " relay_ack=" << relay.endpoint << ':'
                    << (outbox.accepted_endpoints.count(relay.endpoint) != 0
                            ? "yes" : "no")
                    << "\n";
        }
      }
    }

    void require_safe_read(AnchorCoordinator& coordinator) {
      const AnchorCoordinatorStatus status = coordinator.preflight(true);
      if (status.decision.state != AnchorClientState::Consistent &&
          status.decision.state != AnchorClientState::LocalCatchUp &&
          status.decision.state != AnchorClientState::Announced &&
          status.decision.state != AnchorClientState::DegradedReadOnly) {
        throw std::runtime_error(
            std::string("read blocked by anchor state ") +
            anchor_client_state_name(status.decision.state) + " (" +
            anchor_state_reason_name(status.decision.reason) + "): " +
            status.decision.detail);
      }
    }

    template <typename ReadAction>
    void execute_path_read_command(const Command& cmd,
                                   const std::string& command_name,
                                   ObjectStore& obj_store,
                                   const std::string& dropbox_token,
                                   ReadAction action) {
      if (cmd.positional.size() < 1 || cmd.positional.size() > 2) {
        throw std::runtime_error(
            command_name + " requires <vault_name> [path]");
      }

      obj_store.fetch(
          dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      require_safe_read(*coordinator);

      const std::string path =
          (cmd.positional.size() == 2) ? cmd.positional[1] : "";
      action(vault_engine, path);
    }

    Config parse_bootstrap_config(const ByteVec& bytes) {
      Config config;
      config.version = 0;
      config.iterations = 0;
      std::istringstream input(std::string(bytes.begin(), bytes.end()));
      std::string line;
      while (std::getline(input, line)) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) continue;
        const std::string key = line.substr(0, separator);
        const std::string value = line.substr(separator + 1);
        if (key == "version") {
          config.version = static_cast<uint8_t>(std::stoul(value));
        } else if (key == "kdf_iter") {
          config.iterations = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "kdf_salt") {
          config.salt = from_hex(value);
        }
      }
      if (config.version != 2 || config.salt.size() < 16 ||
          config.iterations == 0 || config.iterations > 10000000) {
        throw std::runtime_error("invalid bootstrap Vault config");
      }
      return config;
    }

    void validate_bootstrap_identity(const ClientBootstrap& bootstrap,
                                     const std::string& password) {
      if (Sha256::hash(bootstrap.config_bytes) !=
          bootstrap.channel.config_hash) {
        throw std::runtime_error(
            "bootstrap config does not match the Genesis config hash");
      }
      CryptoImpl crypto;
      const Config config = parse_bootstrap_config(bootstrap.config_bytes);
      const Keys keys = crypto.derive_keys(
          config.salt, config.iterations, password);
      const VaultIdentity identity = unwrap_vault_identity(
          bootstrap.wrapped_identity, keys);
      const SchnorrPublicKey public_key =
          schnorr_public_key(identity.signing_secret);
      if (public_key != bootstrap.channel.vault_public_key) {
        throw std::runtime_error(
            "bootstrap identity does not match the channel public key");
      }
      bool genesis_found = false;
      bool checkpoint_found = false;
      for (const auto& event : bootstrap.events) {
        if (!verify_nostr_event(event, public_key)) {
          throw std::runtime_error(
              "bootstrap contains an invalid outer Nostr event");
        }
        const AnchorEventPayload payload = verify_decrypt_anchor_event(
            event, public_key, identity.signing_secret);
        if (const auto* genesis = std::get_if<VaultGenesisEvent>(&payload)) {
          if (event.id != bootstrap.channel.genesis_event_id ||
              event.kind != kGitVaultAnchorEventKind ||
              event.tags != std::vector<NostrTag>{{
                  "t", to_hex(bootstrap.channel.channel_id)}} ||
              genesis->common.vault_id != bootstrap.channel.vault_id ||
              genesis->common.protocol_epoch !=
                  bootstrap.channel.protocol_epoch ||
              genesis->config_hash != bootstrap.channel.config_hash) {
            throw std::runtime_error("bootstrap Genesis is invalid");
          }
          genesis_found = true;
          continue;
        }
        if (const auto* checkpoint =
                std::get_if<HeadCheckpointEvent>(&payload)) {
          const ByteVec replica =
              from_hex(checkpoint->common.installation_id);
          if (event.kind != kGitVaultCheckpointEventKind ||
              replica.size() != ReplicaId{}.size() ||
              checkpoint->common.vault_id != bootstrap.channel.vault_id ||
              checkpoint->common.protocol_epoch !=
                  bootstrap.channel.protocol_epoch ||
              event.tags != std::vector<NostrTag>{
                  {"t", to_hex(bootstrap.channel.channel_id)},
                  {"d", "gitvault:" + to_hex(bootstrap.channel.vault_id) +
                            ":" + checkpoint->common.installation_id}}) {
            throw std::runtime_error(
                "bootstrap checkpoint witness is invalid");
          }
          if (event.id == bootstrap.checkpoint.tip_event_id) {
            if (checkpoint->common.protocol_epoch !=
                    bootstrap.checkpoint.protocol_epoch ||
                checkpoint->head != bootstrap.checkpoint.accepted_head ||
                checkpoint->clock != bootstrap.checkpoint.accepted_clock ||
                checkpoint->head_envelope_hash !=
                    bootstrap.checkpoint.head_envelope_hash) {
              throw std::runtime_error(
                  "bootstrap trusted checkpoint is invalid");
            }
            checkpoint_found = true;
          }
          continue;
        }
        throw std::runtime_error(
            "bootstrap contains an unsupported anchor event");
      }
      if (!genesis_found || !checkpoint_found) {
        throw std::runtime_error(
            "bootstrap is missing its Genesis or trusted checkpoint");
      }
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
        if (cmd.relays.size() != 3) {
            throw std::runtime_error(
                "init requires exactly three --relay wss://... options");
        }
        std::string vault_name = normalize_vault_name(cmd.positional[0]);
        std::filesystem::path local_vault_dir = getHomeDirectory() + "/.gitvault/" + vault_name;
        if (std::filesystem::exists(local_vault_dir)) {
            throw std::runtime_error(
                "local vault metadata already exists: " +
                local_vault_dir.string());
        }
        obj_store.init(dropbox_token, vault_name);
        VaultEngine vault_engine(obj_store, read_password(cmd), true);
        std::cout << "initializing store at " << obj_store.root() << "...\n";
        std::array<uint8_t, 32> commit_hash;
        if (cmd.positional.size() == 1) {
          commit_hash = vault_engine.init_vault();
        }
        else if (cmd.positional.size() == 2) {
          std::filesystem::path plain_dir = cmd.positional[1];
          commit_hash = vault_engine.lock_vault(plain_dir);
        }
        NostrAnchorChannel channel(
            cmd.relays, vault_engine.identity().signing_secret);
        const AnchorChannelConfig anchor = AnchorCoordinator::initialize(
            obj_store, vault_engine, channel, cmd.relays);
        std::cout << "\ncommit=" << to_hex(commit_hash) << "\n";
        std::cout << "genesis=" << to_hex(anchor.genesis_event_id) << "\n";
    } else if (cmd.command == "destroy") {
        if (cmd.positional.size() != 1) {
            throw std::runtime_error("destroy requires <vault_name>");
        }

        const std::string vault_name = normalize_vault_name(cmd.positional[0]);
        const std::filesystem::path local_vault_dir =
            std::filesystem::path(getHomeDirectory()) / ".gitvault" / vault_name;

        std::cout
            << "Warning: 'destroy' will permanently remove:\n"
            << "  local metadata: " << local_vault_dir.string() << "\n"
            << "  remote Dropbox folder: /" << vault_name << "\n\n"
            << "Proceed? (y/N): ";

        std::string answer;
        std::getline(std::cin, answer);
        if (!(answer == "y" || answer == "Y")) {
            std::cout << "Destroy cancelled.\n";
            return;
        }

        const bool remote_deleted = obj_store.destroy(dropbox_token, vault_name);
        const bool local_deleted = obj_store.remove_local_metadata();

        if (remote_deleted) {
            std::cout << "Remote vault folder deleted.\n";
        } else {
            std::cout << "Remote vault folder not found.\n";
        }

        if (local_deleted) {
            std::cout << "Local vault metadata deleted.\n";
        } else {
            std::cout << "Local vault metadata not found.\n";
        }
    } else if (cmd.command == "add") {
        if (cmd.positional.size() != 3) {
            throw std::runtime_error("add requires <vault_name> <local_path> <cloud_path>");
        }
        obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
        VaultEngine vault_engine(obj_store, read_password(cmd));
        auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
        auto commit_hash = coordinator->execute_write(
            [&](const AnchorHash& base) {
              return vault_engine.prepare_add(
                  std::filesystem::path(cmd.positional[1]),
                  cmd.positional[2], base);
            }).new_head;
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "mkdir") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("mkdir requires <vault_name> <cloud_dir_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      auto commit_hash = coordinator->execute_write(
          [&](const AnchorHash& base) {
            return vault_engine.prepare_mkdir(cmd.positional[1], base);
          }).new_head;
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "remove") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("remove requires <vault_name> <cloud_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      auto commit_hash = coordinator->execute_write(
          [&](const AnchorHash& base) {
            return vault_engine.prepare_remove(cmd.positional[1], base);
          }).new_head;
      std::cout << "commit=" << to_hex(commit_hash) << "\n";
    } else if (cmd.command == "rmdir") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("rmdir requires <vault_name> <cloud_dir_path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      const std::string cloud_dir_path = cmd.positional[1];

      try {
        auto commit_hash = coordinator->execute_write(
            [&](const AnchorHash& base) {
              return vault_engine.prepare_rmdir(cloud_dir_path, false, base);
            }).new_head;
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

        auto commit_hash = coordinator->execute_write(
            [&](const AnchorHash& base) {
              return vault_engine.prepare_rmdir(cloud_dir_path, true, base);
            }).new_head;
        std::cout << "commit=" << to_hex(commit_hash) << "\n";
      }
    } else if (cmd.command == "ls") {
      execute_path_read_command(
          cmd, "ls", obj_store, dropbox_token,
          [](VaultEngine& vault_engine, const std::string& path) {
            Tree tree = vault_engine.list_directory(path);

            std::cout << std::left
                      << std::setw(25) << "NAME"
                      << std::setw(12) << "SIZE"
                      << "Modification Time\n";
            std::cout << std::string(57, '-') << "\n";
            for (const auto& entry : tree.entries) {
              std::string name = entry.name;
              if (entry.type == 1) {
                name += "/";
              }
              std::cout << std::left << std::setw(25) << name;
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
          });
    } else if (cmd.command == "tree") {
      execute_path_read_command(
          cmd, "tree", obj_store, dropbox_token,
          [](VaultEngine& vault_engine, const std::string& path) {
            vault_engine.print_tree(path, std::cout);
          });
    } else if (cmd.command == "cat") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error("cat requires <vault_name> <path>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      require_safe_read(*coordinator);
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
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      require_safe_read(*coordinator);
      ScanStats stats = (cmd.command == "quick-scan")
                            ? vault_engine.quick_scan()
                            : vault_engine.deep_scan();
      std::cout << "commits=" << stats.commits_checked << " trees=" << stats.trees_checked
                << " blobs=" << stats.blobs_checked
                << " missing=" << stats.blobs_missing << " hashed=" << stats.blobs_hashed
                << " errors=" << stats.errors << "\n";
    } else if (cmd.command == "export-client") {
      if (cmd.positional.size() != 2) {
        throw std::runtime_error(
            "export-client requires <vault_name> <bootstrap_file>");
      }
      const std::string vault_name =
          normalize_vault_name(cmd.positional[0]);
      obj_store.fetch(dropbox_token, vault_name);
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      (void)coordinator->preflight(false);
      const AnchorCoordinatorStatus status = coordinator->preflight(false);
      if (status.relay_fetch.synchronized_count() <
              coordinator->config().read_quorum ||
          status.decision.state != AnchorClientState::Consistent) {
        throw std::runtime_error(
            "export-client requires R=2 and CONSISTENT state");
      }
      AnchorTrustStore trust(obj_store.trust_directory(),
                             vault_engine.trust_mac_key());
      ClientBootstrap bootstrap;
      bootstrap.vault_name = vault_name;
      bootstrap.config_bytes = obj_store.read_local_config_bytes();
      bootstrap.wrapped_identity = obj_store.load_vault_identity();
      bootstrap.channel = trust.load_channel();
      bootstrap.checkpoint = trust.load_checkpoint();
      bootstrap.events = trust.load_cached_events();
      {
        const auto witnesses = trust.load_witnesses();
        bootstrap.events.insert(bootstrap.events.end(), witnesses.begin(),
                                witnesses.end());
      }
      write_client_bootstrap(cmd.positional[1], bootstrap);
      std::cout << "bootstrap=" << cmd.positional[1] << "\n";
    } else if (cmd.command == "import-client") {
      if (cmd.positional.size() != 1) {
        throw std::runtime_error(
            "import-client requires <bootstrap_file>");
      }
      const ClientBootstrap bootstrap =
          read_client_bootstrap(cmd.positional[0]);
      const std::string password = read_password(cmd);
      validate_bootstrap_identity(bootstrap, password);
      const std::filesystem::path local_vault_dir =
          std::filesystem::path(getHomeDirectory()) / ".gitvault" /
          bootstrap.vault_name;
      if (std::filesystem::exists(local_vault_dir)) {
        throw std::runtime_error(
            "import destination already contains local metadata: " +
            local_vault_dir.string());
      }
      obj_store.fetch(dropbox_token, bootstrap.vault_name);
      if (!constant_time_equal(obj_store.read_cloud_config_bytes(),
                               bootstrap.config_bytes)) {
        throw std::runtime_error(
            "Dropbox config differs from the bootstrap config");
      }
      try {
        obj_store.write_local_config_bytes(bootstrap.config_bytes);
        obj_store.save_vault_identity(bootstrap.wrapped_identity);
        VaultEngine vault_engine(obj_store, password);
        AnchorTrustStore trust(obj_store.trust_directory(),
                               vault_engine.trust_mac_key());
        AnchorChannelConfig local_channel = bootstrap.channel;
        local_channel.installation_id = to_hex(random_bytes(16));
        trust.save_channel(local_channel);
        trust.save_checkpoint(bootstrap.checkpoint);
        for (const auto& event : bootstrap.events) {
          if (event.kind == kGitVaultCheckpointEventKind) {
            const AnchorEventPayload decoded = verify_decrypt_anchor_event(
                event, local_channel.vault_public_key,
                vault_engine.identity().signing_secret);
            const auto* checkpoint =
                std::get_if<HeadCheckpointEvent>(&decoded);
            if (checkpoint == nullptr ||
                checkpoint->common.installation_id.size() != 32) {
              throw std::runtime_error("invalid bootstrap checkpoint witness");
            }
            const ByteVec id_bytes =
                from_hex(checkpoint->common.installation_id);
            ReplicaId id{};
            std::copy(id_bytes.begin(), id_bytes.end(), id.begin());
            trust.save_witness(id, event);
          } else {
            trust.cache_event(event);
          }
        }
        const VersionedBytes imported_cloud =
            obj_store.read_cloud_head_versioned();
        const VaultHeadState imported_state =
            vault_engine.decrypt_head_state(imported_cloud.bytes);
        if (imported_state.protocol_epoch !=
                bootstrap.checkpoint.protocol_epoch ||
            imported_state.head != bootstrap.checkpoint.accepted_head ||
            imported_state.clock != bootstrap.checkpoint.accepted_clock) {
          throw std::runtime_error(
              "Dropbox HEAD differs from the bootstrap vector checkpoint");
        }
        obj_store.write_local_head(imported_cloud.bytes);
        auto channel = std::make_unique<NostrAnchorChannel>(
            local_channel.relay_urls,
            vault_engine.identity().signing_secret);
        AnchorCoordinator coordinator(
            obj_store, vault_engine, std::move(channel));
        (void)coordinator.preflight(false);
        const AnchorCoordinatorStatus installed =
            coordinator.preflight(false);
        if (installed.relay_fetch.synchronized_count() <
                coordinator.config().read_quorum ||
            installed.decision.state != AnchorClientState::Consistent) {
          throw std::runtime_error(
              "import validation did not reach R=2 CONSISTENT state");
        }
        std::cout << "imported=" << bootstrap.vault_name << "\n"
                  << "installation_id="
                  << local_channel.installation_id << "\n";
      } catch (...) {
        try {
          (void)obj_store.remove_local_metadata();
        } catch (...) {
        }
        throw;
      }
    } else if (cmd.command == "sync") {
      if (cmd.positional.size() != 1) {
        throw std::runtime_error(cmd.command + " requires <vault_name>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      const AnchorCoordinatorStatus status = coordinator->preflight(false);
      print_anchor_status(status);
      if (status.decision.state != AnchorClientState::Consistent &&
          status.decision.state != AnchorClientState::LocalCatchUp &&
          status.decision.state != AnchorClientState::Announced) {
        throw std::runtime_error(
            std::string("sync stopped in ") +
            anchor_client_state_name(status.decision.state) + " (" +
            anchor_state_reason_name(status.decision.reason) + ")");
      }
    } else if (cmd.command == "status") {
      if (cmd.positional.size() != 1) {
        throw std::runtime_error("status requires <vault_name>");
      }
      obj_store.fetch(dropbox_token, normalize_vault_name(cmd.positional[0]));
      VaultEngine vault_engine(obj_store, read_password(cmd));
      auto coordinator = make_anchor_coordinator(obj_store, vault_engine);
      print_anchor_status(coordinator->preflight(true));
    } else {
        print_usage();
    }

    return;
}
