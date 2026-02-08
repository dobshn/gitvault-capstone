#pragma once

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include "httplib.h"

#include <string>
#include <string_view>

#include "util.h"

class DropboxStorage {
 public:
  DropboxStorage(std::string access_token, std::string root_path);

  void init();
  void put(std::string_view path, const ByteVec& data, bool overwrite = true) const;
  ByteVec get(std::string_view path) const;
  bool exists(std::string_view path) const;

 private:
  static void check(const httplib::Result& res, int expected, std::string_view ctx);
  static void require_relative_path(std::string_view path);
  static void require_root_path(std::string_view path);

  std::string build_dropbox_path(std::string_view path) const;
  void require_initialized(std::string_view op) const;

  std::string access_token_;
  std::string root_path_;
  mutable httplib::SSLClient api_client_;
  mutable httplib::SSLClient content_client_;
  bool initialized_ = false;
};
