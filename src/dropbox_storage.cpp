#include "dropbox_storage.h"

#include "dropbox_retry.h"
#include "json.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <utility>

namespace {
  using nlohmann::json;

  std::string require_revision(const json& metadata,
                               std::string_view operation) {
    if (!metadata.is_object() || !metadata.contains("rev") ||
        !metadata.at("rev").is_string() ||
        metadata.at("rev").get<std::string>().empty()) {
      throw std::runtime_error(std::string(operation) +
                               " response is missing file revision");
    }
    return metadata.at("rev").get<std::string>();
  }
}

  void DropboxStorage::check(const httplib::Result& res, int expected, std::string_view ctx) {
    if (!res) {
      throw std::runtime_error(std::string(ctx) + " request failed (network/TLS)");
    }
    if (res->status == expected) {
      return;
    }

    std::string body = res->body;
    if (body.size() > 4096) {
      body.resize(4096);
      body += "...";
    }
    throw std::runtime_error(std::string(ctx) + " failed. HTTP " + std::to_string(res->status) + ": " + body);
  }

  void DropboxStorage::require_relative_path(std::string_view path) {
    if (path.empty() || path.front() == '/') {
      throw std::runtime_error("invalid path: must be relative (e.g. \"a/b.txt\")");
    }
    if (path.find('\\') != std::string_view::npos) {
      throw std::runtime_error("invalid path: '\\\\' not allowed");
    }
    if (path.find("//") != std::string_view::npos) {
      throw std::runtime_error("invalid path: '//' not allowed");
    }
    if (path == "." || path == ".." || path.find("/./") != std::string_view::npos ||
        path.find("/../") != std::string_view::npos ||
        (path.size() >= 2 && path.substr(path.size() - 2) == "/.") ||
        (path.size() >= 3 && path.substr(path.size() - 3) == "/..")) {
      throw std::runtime_error("invalid path: '.' and '..' not allowed");
    }
  }

  void DropboxStorage::require_root_path(std::string_view path) {
    if (path.size() < 2 || path.front() != '/' || path.back() == '/') {
      throw std::runtime_error("invalid root path: use format like \"/my_root\"");
    }
    require_relative_path(path.substr(1));
  }

  std::string DropboxStorage::build_dropbox_path(std::string_view path) const {
    require_relative_path(path);
    return root_path_ + "/" + std::string(path);
  }

  void DropboxStorage::require_initialized(std::string_view op) const {
    if (!fetched) {
      throw std::runtime_error(std::string(op) + " requires init() first");
    }
  }

// 현재 클라우드에 해당 root 폴더가 생성되어 있는 지 확인 
void DropboxStorage::fetch(std::string access_token, std::string root_path) {
  if (fetched) {
    return;
  }
  
  thread_local httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(true);

  access_token_ = access_token;
  root_path_ = root_path;

  if (access_token_.empty()) {
    throw std::runtime_error("dropbox access token is empty");
  }
  require_root_path(root_path_);

  {
    auto res = client.Post("/2/users/get_current_account",
                                {{"Authorization", "Bearer " + access_token_}},
                                "null",
                                "application/json");
    check(res, 200, "Token validation");
  }

  auto check_folder_exists = [&](const std::string& path, const std::string& name) {
    auto res = client.Post("/2/files/get_metadata",
                                {{"Authorization", "Bearer " + access_token_}},
                                json{{"path", path}}.dump(),
                                "application/json");

    if (!res) {
      throw std::runtime_error(name + " metadata request failed (network/TLS)");
    }

    if (res->status == 409) {
      throw std::runtime_error(name + " does not exist in cloud.");
    }

    if (res->status != 200) {
      throw std::runtime_error(name + " metadata failed. HTTP " +
                               std::to_string(res->status) + ": " + res->body);
    }

    // 타입 검증 (folder인지 확인)
    auto body = json::parse(res->body);
    if (body[".tag"] != "folder") {
      throw std::runtime_error(name + " exists but is not a folder.");
    }
  };

  // root 폴더 존재 확인
  check_folder_exists(root_path_, "Root folder");

  // objects 폴더 존재 확인
  check_folder_exists(root_path_ + "/objects", "Objects folder");

  fetched = true;
}

// 현재 클라우드에 전달받은 root 폴더를 생성. 이미 있는 경우 예외 던짐.
void DropboxStorage::init(std::string access_token, std::string root_path) {
  if (fetched) {
    return;
  }

  thread_local httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(true);

  access_token_ = access_token;
  root_path_ = root_path;

  if (access_token_.empty()) {
    throw std::runtime_error("dropbox access token is empty");
  }
  require_root_path(root_path_);

  {
    auto res = client.Post("/2/users/get_current_account",
                                {{"Authorization", "Bearer " + access_token}},
                                "null",
                                "application/json");
    check(res, 200, "Token validation");
  }

  {
    auto res = client.Post("/2/files/create_folder_v2",
                                {{"Authorization", "Bearer " + access_token}},
                                json{{"path", root_path}, {"autorename", false}}.dump(),
                                "application/json");
    if (!res) {
      throw std::runtime_error("Create root folder request failed (network/TLS)");
    }
    if (res->status == 409) {
      throw std::runtime_error(
          "Vault root folder already exists: " + root_path + "\n" +
          "Use `gitvault tree " + root_path + "` to inspect it."
      );
    }
    if (res->status != 200) {
      throw std::runtime_error("Create root folder failed. HTTP " + std::to_string(res->status) + ": " +
                               res->body);
    }
  }

  {
    auto res = client.Post("/2/files/create_folder_v2",
                                {{"Authorization", "Bearer " + access_token}},
                                json{{"path", root_path + "/objects"}, {"autorename", false}}.dump(),
                                "application/json");
    if (!res) {
      throw std::runtime_error("Create objects folder request failed (network/TLS)");
    }
    if (res->status != 200) {
      throw std::runtime_error("Create objects folder failed. HTTP " + std::to_string(res->status) + ": " +
                               res->body);
    }
  }

  fetched = true;
}

bool DropboxStorage::destroy(std::string access_token, std::string root_path) {
  thread_local httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(true);

  access_token_ = std::move(access_token);
  root_path_ = std::move(root_path);
  fetched = false;

  if (access_token_.empty()) {
    throw std::runtime_error("dropbox access token is empty");
  }
  require_root_path(root_path_);

  {
    auto res = client.Post("/2/users/get_current_account",
                                {{"Authorization", "Bearer " + access_token_}},
                                "null",
                                "application/json");
    check(res, 200, "Token validation");
  }

  auto res = client.Post("/2/files/delete_v2",
                              {{"Authorization", "Bearer " + access_token_}},
                              json{{"path", root_path_}}.dump(),
                              "application/json");
  if (!res) {
    throw std::runtime_error("Delete vault request failed (network/TLS)");
  }
  if (res->status == 200) {
    return true;
  }
  if (res->status == 409) {
    return false;
  }

  std::string body = res->body;
  if (body.size() > 4096) {
    body.resize(4096);
    body += "...";
  }
  throw std::runtime_error("Delete vault failed. HTTP " + std::to_string(res->status) + ": " + body);
}

namespace {
httplib::Result upload_with_rate_limit_retry(
    const httplib::Headers& headers,
    const ByteVec& data,
    std::string_view operation) {
  const char* body =
      data.empty() ? "" : reinterpret_cast<const char*>(data.data());
  for (int attempt = 1; attempt <= kDropboxUploadMaxAttempts; ++attempt) {
    thread_local httplib::SSLClient client("content.dropboxapi.com", 443);
    client.set_keep_alive(true);
    auto res = client.Post("/2/files/upload",
                           headers,
                           body,
                           data.size(),
                           "application/octet-stream");
    if (!res) {
      throw std::runtime_error(std::string(operation) +
                               " failed (network/TLS)");
    }
    if (res->status != 429) {
      return res;
    }
    if (attempt == kDropboxUploadMaxAttempts) {
      throw std::runtime_error(
          std::string(operation) + " failed after " +
          std::to_string(attempt) + " attempts. HTTP 429: " + res->body);
    }

    const int delay_seconds = dropbox_retry_delay_seconds(
        res->get_header_value("Retry-After"), res->body, attempt);
    std::cerr << "\n" << operation << " rate limited; retrying after "
              << delay_seconds << "s (attempt " << attempt << "/"
              << kDropboxUploadMaxAttempts << ")" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(delay_seconds));
  }
  throw std::runtime_error("upload retry loop exhausted");
}
}  // namespace

// path에 data를 overwrite 유무에 맞추어 업로드 (150MB 제한)
void DropboxStorage::put(std::string_view path,
                         const ByteVec& data,
                         bool overwrite) const {
  require_initialized("put()");

  const httplib::Headers headers = {
      {"Authorization", "Bearer " + access_token_},
      {"Dropbox-API-Arg",
       json{{"path", build_dropbox_path(path)},
            {"mode", overwrite ? "overwrite" : "add"},
            {"autorename", !overwrite}}
           .dump()},
  };
  const auto res = upload_with_rate_limit_retry(headers, data, "Upload");
  if (res->status != 200) {
    throw std::runtime_error(
        "Upload /2/files/upload failed. HTTP " +
        std::to_string(res->status) + ": " + res->body);
  }
}

ConditionalWriteResult DropboxStorage::upload_conditionally(
    std::string_view path,
    const ByteVec& data,
    const json& mode) const {
  require_initialized("conditional upload");

  httplib::Headers headers = {
      {"Authorization", "Bearer " + access_token_},
      {"Dropbox-API-Arg",
       json{{"path", build_dropbox_path(path)},
            {"mode", mode},
            {"autorename", false}}
           .dump()},
  };

  const auto res =
      upload_with_rate_limit_retry(headers, data, "Conditional upload");
  if (res->status == 409) {
    return {ConditionalWriteStatus::Conflict, {}};
  }
  if (res->status != 200) {
    throw std::runtime_error(
        "Conditional upload /2/files/upload failed. HTTP " +
        std::to_string(res->status) + ": " + res->body);
  }
  const json metadata = json::parse(res->body);
  return {ConditionalWriteStatus::Updated,
          require_revision(metadata, "Conditional upload")};
}

ConditionalWriteResult DropboxStorage::put_if_revision(
    std::string_view path,
    const ByteVec& data,
    std::string_view expected_revision) const {
  if (expected_revision.empty()) {
    throw std::runtime_error("expected Dropbox revision must not be empty");
  }
  return upload_conditionally(
      path, data,
      json{{".tag", "update"},
           {"update", std::string(expected_revision)}});
}

ConditionalWriteResult DropboxStorage::put_if_absent(
    std::string_view path,
    const ByteVec& data) const {
  return upload_conditionally(path, data, "add");
}

// path에 있는 파일을 다운 받아옴
ByteVec DropboxStorage::get(std::string_view path) const {
  return get_versioned(path).bytes;
}

VersionedBytes DropboxStorage::get_versioned(std::string_view path) const {
  require_initialized("get()");

  thread_local httplib::SSLClient client("content.dropboxapi.com", 443);
  client.set_keep_alive(true);

  httplib::Headers headers = {
      {"Authorization", "Bearer " + access_token_},
      {"Dropbox-API-Arg", json{{"path", build_dropbox_path(path)}}.dump()},
  };

  auto res = client.Post("/2/files/download", headers);
  check(res, 200, "Download /2/files/download");

  const std::string metadata_header =
      res->get_header_value("Dropbox-API-Result");
  if (metadata_header.empty()) {
    throw std::runtime_error(
        "Download response is missing Dropbox-API-Result metadata");
  }
  const json metadata = json::parse(metadata_header);

  const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
  return {ByteVec(bytes, bytes + res->body.size()),
          require_revision(metadata, "Download")};
}

// path 경로의 파일이 존재하는지 확인. 있으면 true, 없으면 false
bool DropboxStorage::exists(std::string_view path) const {
  require_initialized("exists()");

  thread_local httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(true);

  auto res = client.Post("/2/files/get_metadata",
                              {{"Authorization", "Bearer " + access_token_}},
                              json{{"path", build_dropbox_path(path)}}.dump(),
                              "application/json");
  if (!res) {
    throw std::runtime_error("Metadata request failed (network/TLS)");
  }
  if (res->status == 200) {
    return true;
  }
  if (res->status == 409) {
    return false;
  }

  std::string body = res->body;
  if (body.size() > 4096) {
    body.resize(4096);
    body += "...";
  }
  throw std::runtime_error("Metadata request failed. HTTP " + std::to_string(res->status) + ": " + body);
}

// 루트 기준 상대 경로의 파일/폴더를 삭제한다.
// 삭제 성공 시 true, 대상이 없으면 false(HTTP 409)를 반환한다.
// 네트워크/TLS 오류나 기타 HTTP 오류는 std::runtime_error를 던진다.
bool DropboxStorage::remove(std::string_view path) const {
  require_initialized("remove()");

  thread_local httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(true);
  
  auto res = client.Post("/2/files/delete_v2",
                              {{"Authorization", "Bearer " + access_token_}},
                              json{{"path", build_dropbox_path(path)}}.dump(),
                              "application/json");
  if (!res) {
    throw std::runtime_error("Delete request failed (network/TLS)");
  }
  if (res->status == 200) {
    return true;
  }
  if (res->status == 409) {
    return false;
  }

  std::string body = res->body;
  if (body.size() > 4096) {
    body.resize(4096);
    body += "...";
  }
  throw std::runtime_error("Delete request failed. HTTP " + std::to_string(res->status) + ": " + body);
}
