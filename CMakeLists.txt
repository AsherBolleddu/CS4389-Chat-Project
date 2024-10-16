cmake_minimum_required(VERSION 3.15)
project(CS4389-Chat-Project)

set(CMAKE_C_STANDARD 11)

# Get all common source files automatically
file(GLOB COMMON_SOURCES "src/common/*.c")
file(GLOB COMMON_HEADERS "src/common/*.h")

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found!")
endif()

# Server executable
add_executable(server src/server.c ${COMMON_SOURCES} ${COMMON_HEADERS})
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto pthread)

# Client executable
add_executable(client src/client.c ${COMMON_SOURCES} ${COMMON_HEADERS})
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto pthread)
