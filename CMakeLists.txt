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
