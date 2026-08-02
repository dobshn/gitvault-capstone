#pragma once
#include <string>
#include <string_view>

#include "util.h"

struct VersionedBytes {
    ByteVec bytes;
    std::string revision;
};

enum class ConditionalWriteStatus {
    Updated,
    Conflict,
};

struct ConditionalWriteResult {
    ConditionalWriteStatus status = ConditionalWriteStatus::Conflict;
    std::string revision;
};

class API {
private:
public:
    virtual void init(std::string access_token, std::string root_path) = 0;
    virtual void fetch(std::string access_token, std::string root_path) = 0;
    virtual bool destroy(std::string access_token, std::string root_path) = 0;
    virtual void put(std::string_view path, const ByteVec& data, bool overwrite = true) const = 0;
    virtual ByteVec get(std::string_view path) const = 0;
    virtual VersionedBytes get_versioned(std::string_view path) const = 0;
    virtual ConditionalWriteResult put_if_revision(
        std::string_view path,
        const ByteVec& data,
        std::string_view expected_revision) const = 0;
    virtual ConditionalWriteResult put_if_absent(
        std::string_view path,
        const ByteVec& data) const = 0;
    virtual bool exists(std::string_view path) const = 0;
    virtual bool remove(std::string_view path) const = 0;
    virtual ~API() = default;
};
