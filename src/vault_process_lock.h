#pragma once

#include <filesystem>

class VaultProcessLock {
public:
  explicit VaultProcessLock(const std::filesystem::path& path);
  ~VaultProcessLock();

  VaultProcessLock(const VaultProcessLock&) = delete;
  VaultProcessLock& operator=(const VaultProcessLock&) = delete;

private:
  int descriptor_ = -1;
};

