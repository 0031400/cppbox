#include "inbound/tun_route.hpp"

#ifdef _WIN32

#include "core/log.hpp"

#include <boost/asio/ip/address_v4.hpp>
#include <cstring>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace sbox {
namespace {

std::uint32_t ipv4_to_net_order_u32(const std::string &text) {
  auto addr = boost::asio::ip::make_address_v4(text);
  auto bytes = addr.to_bytes();

  std::uint32_t value{};
  std::memcpy(&value, bytes.data(), sizeof(value));
  return value;
}

bool ok_or_exists(DWORD error) {
  return error == NO_ERROR || error == ERROR_OBJECT_ALREADY_EXISTS;
}

void log_win32_error(const char *what, DWORD error) {
  if (error != NO_ERROR) {
    log_error(std::string(what) + " failed: " + std::to_string(error));
  }
}

bool add_tun_address(const NET_LUID &luid, const std::string &tun_ip) {
  MIB_UNICASTIPADDRESS_ROW row{};
  InitializeUnicastIpAddressEntry(&row);

  row.InterfaceLuid = luid;
  row.Address.si_family = AF_INET;
  row.Address.Ipv4.sin_family = AF_INET;
  row.Address.Ipv4.sin_addr.s_addr = ipv4_to_net_order_u32(tun_ip);
  row.OnLinkPrefixLength = 24;
  row.PrefixOrigin = IpPrefixOriginManual;
  row.SuffixOrigin = IpSuffixOriginManual;
  row.DadState = IpDadStatePreferred;

  const auto error = CreateUnicastIpAddressEntry(&row);
  if (!ok_or_exists(error)) {
    log_win32_error("CreateUnicastIpAddressEntry", error);
    return false;
  }

  return true;
}
bool delete_tun_address(const NET_LUID &luid, const std::string &tun_ip) {
  MIB_UNICASTIPADDRESS_ROW row{};
  InitializeUnicastIpAddressEntry(&row);

  row.InterfaceLuid = luid;
  row.Address.si_family = AF_INET;
  row.Address.Ipv4.sin_family = AF_INET;
  row.Address.Ipv4.sin_addr.s_addr = ipv4_to_net_order_u32(tun_ip);

  const auto error = DeleteUnicastIpAddressEntry(&row);
  if (error != NO_ERROR && error != ERROR_NOT_FOUND) {
    log_win32_error("DeleteUnicastIpAddressEntry", error);
    return false;
  }

  return true;
}

} // namespace
bool add_default_route(const NET_LUID &luid, const std::string &tun_next_ip) {
  MIB_IPFORWARD_ROW2 row{};
  InitializeIpForwardEntry(&row);

  row.InterfaceLuid = luid;
  row.DestinationPrefix.Prefix.si_family = AF_INET;
  row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
  row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;
  row.DestinationPrefix.PrefixLength = 0;

  row.NextHop.si_family = AF_INET;
  row.NextHop.Ipv4.sin_family = AF_INET;
  row.NextHop.Ipv4.sin_addr.s_addr = ipv4_to_net_order_u32(tun_next_ip);

  row.Metric = 1;
  row.Protocol = MIB_IPPROTO_NETMGMT;

  const auto error = CreateIpForwardEntry2(&row);
  if (!ok_or_exists(error)) {
    log_win32_error("CreateIpForwardEntry2(default route)", error);
    return false;
  }

  return true;
}

bool delete_default_route(const NET_LUID &luid, const std::string &tun_next_ip) {
  MIB_IPFORWARD_ROW2 row{};
  InitializeIpForwardEntry(&row);

  row.InterfaceLuid = luid;
  row.DestinationPrefix.Prefix.si_family = AF_INET;
  row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
  row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;
  row.DestinationPrefix.PrefixLength = 0;

  row.NextHop.si_family = AF_INET;
  row.NextHop.Ipv4.sin_family = AF_INET;
  row.NextHop.Ipv4.sin_addr.s_addr = ipv4_to_net_order_u32(tun_next_ip);

  const auto error = DeleteIpForwardEntry2(&row);
  if (error != NO_ERROR && error != ERROR_NOT_FOUND) {
    log_win32_error("DeleteIpForwardEntry2(default route)", error);
    return false;
  }

  return true;
}
std::optional<std::uint32_t>
find_best_interface_index_for_ipv4(const std::string &destination) {
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = ipv4_to_net_order_u32(destination);

  DWORD index = 0;
  DWORD error = GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&dst), &index);
  if (error != NO_ERROR) {
    log_win32_error("GetBestInterfaceEx", error);
    return std::nullopt;
  }

  return index;
}
bool configure_tun_routes(const NET_LUID &luid, const std::string &tun_ip,
                          const std::string &tun_next_ip) {
  if (!add_tun_address(luid, tun_ip)) {
    return false;
  }

  if (!add_default_route(luid, tun_next_ip)) {
    delete_tun_address(luid, tun_ip);
    return false;
  }

  log_info("tun address configured: " + tun_ip + "/24");
  log_info("tun default route configured: 0.0.0.0/0 via " + tun_next_ip);
  return true;
}

bool cleanup_tun_routes(const NET_LUID &luid, const std::string &tun_ip,
                        const std::string &tun_next_ip) {
  const auto route_ok = delete_default_route(luid, tun_next_ip);
  const auto address_ok = delete_tun_address(luid, tun_ip);

  if (route_ok) {
    log_info("tun default route removed: 0.0.0.0/0 via " + tun_next_ip);
  }

  if (address_ok) {
    log_info("tun address removed: " + tun_ip + "/24");
  }

  return route_ok && address_ok;
}

} // namespace sbox

#endif