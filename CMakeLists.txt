cmake_minimum_required(VERSION 3.16)
project(gitvault LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

add_executable(gitvault ${SRC})

target_include_directories(gitvault PRIVATE src)

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
target_compile_definitions(gitvault PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(gitvault PRIVATE OpenSSL::SSL OpenSSL::Crypto)

include(CTest)
if(BUILD_TESTING)
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
endif()
