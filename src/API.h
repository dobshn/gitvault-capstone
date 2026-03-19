#pragma once
#include "util.h"

class API {
private:
public:
    virtual void init(std::string access_token, std::string root_path) = 0;
    virtual void fetch(std::string access_token, std::string root_path) = 0;
    virtual bool destroy(std::string access_token, std::string root_path) = 0;
    virtual void put(std::string_view path, const ByteVec& data, bool overwrite = true) const = 0;
    virtual ByteVec get(std::string_view path) const = 0;
    virtual bool exists(std::string_view path) const = 0;
    virtual bool remove(std::string_view path) const = 0;
    virtual ~API() = default;
};
