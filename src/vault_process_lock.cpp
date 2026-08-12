#include "vault_process_lock.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

VaultProcessLock::VaultProcessLock(const std::filesystem::path& path) {
#if !defined(_WIN32)
  descriptor_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
  if (descriptor_ < 0) {
    throw std::runtime_error("failed to open Vault process lock: " +
                             std::string(std::strerror(errno)));
  }
  if (::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
    const int saved_errno = errno;
    ::close(descriptor_);
    descriptor_ = -1;
    throw std::runtime_error(
        "another GitVault process is already writing this Vault: " +
        std::string(std::strerror(saved_errno)));
  }
#else
  (void)path;
#endif
}

VaultProcessLock::~VaultProcessLock() {
#if !defined(_WIN32)
  if (descriptor_ >= 0) {
    (void)::flock(descriptor_, LOCK_UN);
    (void)::close(descriptor_);
  }
#endif
}
