cmake_minimum_required(VERSION 3.16)
project(gitvault LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(gitvault
  src/main.cpp
  src/vault.cpp
  src/object_store.cpp
  src/format.cpp
  src/util.cpp
  src/crypto/sha256.cpp
  src/crypto/hmac.cpp
  src/crypto/pbkdf2.cpp
  src/crypto/ctr.cpp
)

target_include_directories(gitvault PRIVATE src)

find_package(OpenSSL REQUIRED)
target_link_libraries(gitvault PRIVATE OpenSSL::Crypto)
