#pragma once

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include "httplib.h"
#include <string>
#include <string_view>

#include "API.h"
#include "util.h"

class DropboxStorage : public API {
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
    bool fetched = false;

public:
    DropboxStorage();

    void init(std::string access_token, std::string root_path) override;
    void fetch(std::string access_token, std::string root_path) override;
    void put(std::string_view path, const ByteVec& data, bool overwrite = true) const override;
    ByteVec get(std::string_view path) const override;
    bool exists(std::string_view path) const override;
    bool remove(std::string_view path) const override;
};
