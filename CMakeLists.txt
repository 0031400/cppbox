cmake_minimum_required(VERSION 3.10)
project(cppbox LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Boost CONFIG REQUIRED COMPONENTS system json)
find_package(OpenSSL REQUIRED)
add_executable(cppbox
    src/main.cpp
    src/common/json_common.cpp
    src/config/config.cpp
    src/core/address.cpp
    src/core/log.cpp
    src/core/shutdown.cpp
    src/core/tls.cpp
    src/core/utils.cpp
    src/dns/dns.cpp
    src/dns/dns_inbound.cpp
    src/dns/dns_message.cpp
    src/inbound/http_inbound.cpp
    src/inbound/mixed_inbound.cpp
    src/inbound/socks5_inbound.cpp
    src/inbound/tun_wintun.cpp
    src/inbound/listen.cpp
    src/inbound/tun_route.cpp
    src/inbound/tun_nat.cpp
    src/inbound/tun_inbound.cpp
    src/inbound/tun_checksum.cpp
    src/outbound/block_outbound.cpp
    src/outbound/direct_outbound.cpp
    src/outbound/vless_outbound.cpp
    src/protocol/vless.cpp
    src/protocol/vless.cpp
    src/protocol/socks5.cpp
    src/protocol/tls_sniffer.cpp
    src/protocol/http_proxy.cpp
    src/route/router.cpp
    src/route/rule_set.cpp
    src/transport/ws_client.cpp
    src/transport/tcp_client.cpp
    src/transport/connector.cpp
)
if(WIN32)
    target_sources(cppbox PRIVATE
        src/platform/windows_proxy.cpp
    )
endif()
target_include_directories(cppbox PRIVATE src)
target_compile_definitions(
    cppbox PRIVATE BOOST_ASIO_NO_DEPRECATED
)
target_link_libraries(cppbox PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto Boost::json)
if(WIN32)
    target_compile_definitions(cppbox PRIVATE
        _WIN32_WINNT=0x0A00
    )
    target_link_libraries(cppbox PRIVATE crypt32 iphlpapi ws2_32 wininet)
endif()
if(MSVC)
    target_compile_options(cppbox PRIVATE /bigobj)
endif()
