#pragma once

#ifdef _WIN32


#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <cstdint>

#include "inbound/wintun.h"

namespace cppbox {

struct TunPacket {
  std::uint8_t *data{};
  std::uint32_t size{};
};

class WintunApi {
public:
  WintunApi() = default;
  ~WintunApi();

  WintunApi(const WintunApi &) = delete;
  WintunApi &operator=(const WintunApi &) = delete;

  bool load();
  bool open_adapter(const wchar_t *name);
  bool start_session(std::uint32_t capacity);

  TunPacket receive();
  void release(const TunPacket &packet);

  bool write(const std::uint8_t *data, std::uint32_t size);

  HANDLE read_wait_event() const;
  bool adapter_luid(NET_LUID &luid) const;

private:
  HMODULE dll_{};
  WINTUN_ADAPTER_HANDLE adapter_{};
  WINTUN_SESSION_HANDLE session_{};

  WINTUN_CREATE_ADAPTER_FUNC *create_adapter_{};
  WINTUN_CLOSE_ADAPTER_FUNC *close_adapter_{};
  WINTUN_START_SESSION_FUNC *start_session_{};
  WINTUN_END_SESSION_FUNC *end_session_{};
  WINTUN_GET_READ_WAIT_EVENT_FUNC *get_read_wait_event_{};
  WINTUN_RECEIVE_PACKET_FUNC *receive_packet_{};
  WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release_receive_packet_{};
  WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate_send_packet_{};
  WINTUN_SEND_PACKET_FUNC *send_packet_{};
  WINTUN_GET_ADAPTER_LUID_FUNC *get_adapter_luid_{};
};

} // namespace cppbox

#endif