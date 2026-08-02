cmake_minimum_required(VERSION 3.16)
project(gitvault LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

add_executable(gitvault ${SRC})

target_include_directories(gitvault PRIVATE src)

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
find_path(SECP256K1_INCLUDE_DIR secp256k1.h)
find_library(SECP256K1_LIBRARY secp256k1)
if(NOT SECP256K1_INCLUDE_DIR OR NOT SECP256K1_LIBRARY)
  message(FATAL_ERROR "libsecp256k1 with Schnorr support is required")
endif()
add_library(SECP256K1::secp256k1 UNKNOWN IMPORTED)
set_target_properties(SECP256K1::secp256k1 PROPERTIES
  IMPORTED_LOCATION "${SECP256K1_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${SECP256K1_INCLUDE_DIR}"
)
target_compile_definitions(gitvault PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(gitvault PRIVATE OpenSSL::SSL OpenSSL::Crypto SECP256K1::secp256k1)

include(CTest)
if(BUILD_TESTING)
  find_package(Threads REQUIRED)

  add_executable(gitvault_format_tests
    tests/format_test.cpp
    src/format.cpp
    src/util.cpp
  )
  target_include_directories(gitvault_format_tests PRIVATE src)
  target_link_libraries(gitvault_format_tests PRIVATE OpenSSL::Crypto)
  add_test(NAME gitvault_format_tests COMMAND gitvault_format_tests)

  add_executable(gitvault_identity_tests
    tests/vault_identity_test.cpp
    src/vault_identity.cpp
    src/crypto/CryptoImpl.cpp
    src/crypto/ctr.cpp
    src/crypto/hkdf.cpp
    src/crypto/hmac.cpp
    src/crypto/pbkdf2.cpp
    src/crypto/sha256.cpp
    src/util.cpp
  )
  target_include_directories(gitvault_identity_tests PRIVATE src)
  target_link_libraries(gitvault_identity_tests PRIVATE OpenSSL::Crypto)
  add_test(NAME gitvault_identity_tests COMMAND gitvault_identity_tests)

  add_executable(gitvault_nostr_event_tests
    tests/nostr_event_test.cpp
    src/nostr_event.cpp
    src/crypto/schnorr.cpp
    src/crypto/sha256.cpp
    src/util.cpp
  )
  target_include_directories(gitvault_nostr_event_tests PRIVATE src)
  target_link_libraries(gitvault_nostr_event_tests PRIVATE
    OpenSSL::Crypto
    SECP256K1::secp256k1
  )
  add_test(NAME gitvault_nostr_event_tests COMMAND gitvault_nostr_event_tests)

  add_executable(gitvault_local_anchor_channel_tests
    tests/local_file_anchor_channel_test.cpp
    src/local_file_anchor_channel.cpp
    src/nostr_event.cpp
    src/crypto/schnorr.cpp
    src/crypto/sha256.cpp
    src/util.cpp
  )
  target_include_directories(gitvault_local_anchor_channel_tests PRIVATE src)
  target_link_libraries(gitvault_local_anchor_channel_tests PRIVATE
    OpenSSL::Crypto
    SECP256K1::secp256k1
    Threads::Threads
  )
  add_test(NAME gitvault_local_anchor_channel_tests
    COMMAND gitvault_local_anchor_channel_tests)
endif()
