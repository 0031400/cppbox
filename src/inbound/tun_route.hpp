#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <optional>
#include <string>

namespace sbox {

#ifdef _WIN32
bool configure_tun_routes(const NET_LUID &luid, const std::string &tun_ip,
                          const std::string &tun_next_ip);
bool cleanup_tun_routes(const NET_LUID &luid, const std::string &tun_ip,
                        const std::string &tun_next_ip);
std::optional<std::uint32_t> find_default_route_interface_index();
#endif

} // namespace sbox