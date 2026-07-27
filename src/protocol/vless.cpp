#include "protocol/vless.hpp"
#include "core/utils.hpp"

namespace cppbox {

VlessProtocol::VlessProtocol(VlessConfig config) : config_(std::move(config)) {}

std::vector<unsigned char>
VlessProtocol::build_request(const Destination &dst) const {
  std::vector<unsigned char> out;
  out.reserve(64 + dst.host.to_string().size());

  out.push_back(0x00);
  const auto uuid_bytes = parse_uuid(config_.uuid);
  out.insert(out.end(), uuid_bytes.begin(), uuid_bytes.end());

  out.push_back(0x00);
  out.push_back(0x01);
  write_be16(out, dst.port);

  if (dst.host.type() == HostType::IPv4) {
    out.push_back(0x01);
    const auto bytes = dst.host.asio_address().to_v4().to_bytes();
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
  }

  if (dst.host.type() == HostType::IPv6) {
    out.push_back(0x03);
    const auto bytes = dst.host.asio_address().to_v6().to_bytes();
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
  }

  const auto domain = dst.host.domain().value();
  require(domain.size() <= 255, "vless domain too long");
  out.push_back(0x02);
  out.push_back(static_cast<unsigned char>(domain.size()));
  out.insert(out.end(), domain.begin(), domain.end());
  return out;
}

void VlessProtocol::strip_response_header(std::vector<unsigned char> &bytes) {
  require(bytes.size() >= 2, "short vless response header");
  const std::size_t header_len = 2u + bytes[1];
  require(bytes.size() >= header_len, "incomplete vless header");
  bytes.erase(bytes.begin(),
              bytes.begin() + static_cast<std::ptrdiff_t>(header_len));
}

} // namespace cppbox