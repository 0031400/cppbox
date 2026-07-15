#include "protocol/vless.hpp"
#include "core/utils.hpp"
namespace sbox {
VlessProtocol::VlessProtocol(VlessConfig config) : config_(std::move(config)) {}
std::vector<unsigned char>
VlessProtocol::build_request(const Destination &dst) const {
  std::vector<unsigned char> out;
  out.reserve(64 + dst.host.size());
  out.push_back(0x00);
  auto uuid_bytes = parse_uuid(config_.uuid);
  out.insert(out.end(), uuid_bytes.begin(), uuid_bytes.end());
  out.push_back(0x00);
  out.push_back(0x01);
  write_be16(out, dst.port);
  if (dst.type == AddressType::IPv4) {
    out.push_back(0x01);
    auto ip = asio::ip::make_address_v4(dst.host).to_bytes();
    out.insert(out.end(), ip.begin(), ip.end());
    return out;
  }
  if (dst.type == AddressType::IPv6) {
    out.push_back(0x03);
    auto ip = asio::ip::make_address_v6(dst.host).to_bytes();
    out.insert(out.end(), ip.begin(), ip.end());
    return out;
  }
  require(dst.host.size() <= 255, "vless domain too long");
  out.push_back(0x02);
  out.push_back(static_cast<unsigned char>(dst.host.size()));
  out.insert(out.end(), dst.host.begin(), dst.host.end());
  return out;
}
void VlessProtocol::strip_response_header(std::vector<unsigned char> &bytes) {
  require(bytes.size() >= 2, "short vless response header");
  const auto addon_len = bytes[1];
  const std::size_t header_len = 2u + addon_len;
  require(bytes.size() >= header_len, "incomplete vless header");
  bytes.erase(bytes.begin(),
              bytes.begin() + static_cast<std::ptrdiff_t>(header_len));
}
}; // namespace sbox