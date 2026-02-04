cmake_minimum_required(VERSION 3.15)
project(mpc-rest-service)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fetch dependencies
include(FetchContent)

# Fetch cpp-httplib
FetchContent_Declare(
    httplib
    URL https://github.com/yhirose/cpp-httplib/archive/v0.14.0.tar.gz
)

# Fetch nlohmann_json
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)

FetchContent_MakeAvailable(httplib json)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../mpc-lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../mpc-lib/build/src/common
    ${httplib_SOURCE_DIR}
)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Source files
set(SOURCES
    main.cpp
    mpc_wrapper.cpp
    json_utils.cpp
    platform_service.cpp
    persistency.cpp
)

# Create executable
add_executable(mpc_rest_service ${SOURCES})

# Link libraries
target_link_libraries(mpc_rest_service
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../mpc-lib/build/src/common/libcosigner.so
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(mpc_rest_service PRIVATE ws2_32)
elseif(UNIX)
    target_link_libraries(mpc_rest_service PRIVATE pthread)
endif()
