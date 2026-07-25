#include "inbound/tun_wintun.hpp"


#include "core/log.hpp"

#include <cstring>
#include <string>

namespace sbox {

WintunApi::~WintunApi() {
  if (session_) {
    end_session_(session_);
  }

  if (adapter_) {
    close_adapter_(adapter_);
  }

  if (dll_) {
    FreeLibrary(dll_);
  }
}

bool WintunApi::load() {
  dll_ = LoadLibraryW(L"wintun.dll");
  if (!dll_) {
    log_error("LoadLibraryW(wintun.dll) failed: " +
              std::to_string(GetLastError()));
    return false;
  }

  create_adapter_ = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC *>(
      GetProcAddress(dll_, "WintunCreateAdapter"));
  close_adapter_ = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC *>(
      GetProcAddress(dll_, "WintunCloseAdapter"));
  start_session_ = reinterpret_cast<WINTUN_START_SESSION_FUNC *>(
      GetProcAddress(dll_, "WintunStartSession"));
  end_session_ = reinterpret_cast<WINTUN_END_SESSION_FUNC *>(
      GetProcAddress(dll_, "WintunEndSession"));
  get_read_wait_event_ = reinterpret_cast<WINTUN_GET_READ_WAIT_EVENT_FUNC *>(
      GetProcAddress(dll_, "WintunGetReadWaitEvent"));
  receive_packet_ = reinterpret_cast<WINTUN_RECEIVE_PACKET_FUNC *>(
      GetProcAddress(dll_, "WintunReceivePacket"));
  release_receive_packet_ =
      reinterpret_cast<WINTUN_RELEASE_RECEIVE_PACKET_FUNC *>(
          GetProcAddress(dll_, "WintunReleaseReceivePacket"));
  allocate_send_packet_ =
      reinterpret_cast<WINTUN_ALLOCATE_SEND_PACKET_FUNC *>(
          GetProcAddress(dll_, "WintunAllocateSendPacket"));
  send_packet_ = reinterpret_cast<WINTUN_SEND_PACKET_FUNC *>(
      GetProcAddress(dll_, "WintunSendPacket"));
  get_adapter_luid_ = reinterpret_cast<WINTUN_GET_ADAPTER_LUID_FUNC *>(
      GetProcAddress(dll_, "WintunGetAdapterLUID"));

  return create_adapter_ && close_adapter_ && start_session_ && end_session_ &&
         get_read_wait_event_ && receive_packet_ && release_receive_packet_ &&
         allocate_send_packet_ && send_packet_ && get_adapter_luid_;
}

bool WintunApi::open_adapter(const wchar_t *name) {
  adapter_ = create_adapter_(name, L"Wintun", nullptr);
  if (!adapter_) {
    log_error("WintunCreateAdapter failed: " + std::to_string(GetLastError()));
    return false;
  }

  return true;
}

bool WintunApi::start_session(std::uint32_t capacity) {
  session_ = start_session_(adapter_, capacity);
  if (!session_) {
    log_error("WintunStartSession failed: " + std::to_string(GetLastError()));
    return false;
  }

  return true;
}

TunPacket WintunApi::receive() {
  DWORD size = 0;
  BYTE *packet = receive_packet_(session_, &size);

  return TunPacket{
      .data = packet,
      .size = size,
  };
}

void WintunApi::release(const TunPacket &packet) {
  if (packet.data) {
    release_receive_packet_(session_, packet.data);
  }
}

bool WintunApi::write(const std::uint8_t *data, std::uint32_t size) {
  BYTE *packet = allocate_send_packet_(session_, size);
  if (!packet) {
    return false;
  }

  std::memcpy(packet, data, size);
  send_packet_(session_, packet);
  return true;
}

HANDLE WintunApi::read_wait_event() const {
  return get_read_wait_event_(session_);
}

bool WintunApi::adapter_luid(NET_LUID &luid) const {
  if (!adapter_ || !get_adapter_luid_) {
    return false;
  }

  get_adapter_luid_(adapter_, &luid);
  return true;
}

} // namespace sbox
