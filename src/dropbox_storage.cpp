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
  if (!initialized_) {
    throw std::runtime_error(std::string(op) + " requires init() first");
  }
}

DropboxStorage::DropboxStorage(std::string access_token, std::string root_path)
    : access_token_(std::move(access_token)),
      root_path_(std::move(root_path)),
      api_client_("api.dropboxapi.com", 443),
      content_client_("content.dropboxapi.com", 443) {
  api_client_.set_keep_alive(true);
  content_client_.set_keep_alive(true);
  api_client_.set_connection_timeout(5, 0);
  api_client_.set_read_timeout(30, 0);
  api_client_.set_write_timeout(30, 0);
  content_client_.set_connection_timeout(5, 0);
  content_client_.set_read_timeout(60, 0);
  content_client_.set_write_timeout(60, 0);

  if (access_token_.empty()) {
    throw std::runtime_error("dropbox access token is empty");
  }
  require_root_path(root_path_);
}

void DropboxStorage::init() {
  if (initialized_) {
    return;
  }

  {
    auto res = api_client_.Post("/2/users/get_current_account",
                                {{"Authorization", "Bearer " + access_token_}},
                                "null",
                                "application/json");
    check(res, 200, "Token validation");
  }

  {
    auto res = api_client_.Post("/2/files/create_folder_v2",
                                {{"Authorization", "Bearer " + access_token_}},
                                json{{"path", root_path_}, {"autorename", false}}.dump(),
                                "application/json");
    if (!res) {
      throw std::runtime_error("Create root folder request failed (network/TLS)");
    }
    if (res->status != 409 && res->status != 200) {
      throw std::runtime_error("Create root folder failed. HTTP " + std::to_string(res->status) + ": " +
                               res->body);
    }
  }

  {
    auto res = api_client_.Post("/2/files/create_folder_v2",
                                {{"Authorization", "Bearer " + access_token_}},
                                json{{"path", root_path_ + "/objects"}, {"autorename", false}}.dump(),
                                "application/json");
    if (!res) {
      throw std::runtime_error("Create objects folder request failed (network/TLS)");
    }
    if (res->status != 200 && res->status != 409) {
      throw std::runtime_error("Create objects folder failed. HTTP " + std::to_string(res->status) + ": " +
                               res->body);
    }
  }

  initialized_ = true;
}

void DropboxStorage::put(std::string_view path, const ByteVec& data, bool overwrite) const {
  require_initialized("put()");

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
  auto res = content_client_.Post("/2/files/upload", headers, body, data.size(), "application/octet-stream");
  check(res, 200, "Upload /2/files/upload");
}

ByteVec DropboxStorage::get(std::string_view path) const {
  require_initialized("get()");

  httplib::Headers headers = {
      {"Authorization", "Bearer " + access_token_},
      {"Dropbox-API-Arg", json{{"path", build_dropbox_path(path)}}.dump()},
  };

  auto res = content_client_.Post("/2/files/download", headers);
  check(res, 200, "Download /2/files/download");

  const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
  return ByteVec(bytes, bytes + res->body.size());
}

bool DropboxStorage::exists(std::string_view path) const {
  require_initialized("exists()");

  auto res = api_client_.Post("/2/files/get_metadata",
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
