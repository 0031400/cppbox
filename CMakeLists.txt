cmake_minimum_required(VERSION 3.10)
project(sbox LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Boost REQUIRED COMPONENTS system json)
find_package(OpenSSL REQUIRED)
add_executable(sbox
    src/main.cpp
    src/config/config.cpp
    src/route/router.cpp
    src/inbound/socks5_inbound.cpp
    src/inbound/mixed_inbound.cpp
    src/outbound/direct_outbound.cpp
    src/outbound/vless_ws_outbound.cpp
)
target_include_directories(sbox PRIVATE src)
target_link_libraries(sbox PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto Boost::json)
target_compile_definitions(sbox PRIVATE
    _WIN32_WINNT=0x0601
)
if(MSVC)
    target_compile_options(sbox PRIVATE /bigobj /utf-8)
endif()
