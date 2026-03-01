#include "dropbox_storage.h"

#include "json.hpp"

#include <stdexcept>
#include <utility>

namespace {
  using nlohmann::json;
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
  
  httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(false);

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

  httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(false);

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

// path에 data를 overwrite 유무에 맞추어 업로드 (150MB 제한)
void DropboxStorage::put(std::string_view path, const ByteVec& data, bool overwrite) const {
  require_initialized("put()");

  httplib::SSLClient client("content.dropboxapi.com", 443);
  client.set_keep_alive(false);

  httplib::Headers headers = {
      {"Authorization", "Bearer " + access_token_},
      {"Dropbox-API-Arg",
       json{
           {"path", build_dropbox_path(path)},
           {"mode", overwrite ? "overwrite" : "add"},
           {"autorename", !overwrite},
       }
           .dump()},
  };

  const char* body = data.empty() ? "" : reinterpret_cast<const char*>(data.data());
  auto res = client.Post("/2/files/upload", headers, body, data.size(), "application/octet-stream");
  check(res, 200, "Upload /2/files/upload");
}

// path에 있는 파일을 다운 받아옴
ByteVec DropboxStorage::get(std::string_view path) const {
  require_initialized("get()");

  httplib::SSLClient client("content.dropboxapi.com", 443);
  client.set_keep_alive(false);

  httplib::Headers headers = {
      {"Authorization", "Bearer " + access_token_},
      {"Dropbox-API-Arg", json{{"path", build_dropbox_path(path)}}.dump()},
  };

  auto res = client.Post("/2/files/download", headers);
  check(res, 200, "Download /2/files/download");

  const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
  return ByteVec(bytes, bytes + res->body.size());
}

// path 경로의 파일이 존재하는지 확인. 있으면 true, 없으면 false
bool DropboxStorage::exists(std::string_view path) const {
  require_initialized("exists()");

  httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(false);

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

  httplib::SSLClient client("api.dropboxapi.com", 443);
  client.set_keep_alive(false);
  
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
