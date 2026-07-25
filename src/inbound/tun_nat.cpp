#include "inbound/tun_nat.hpp"

#include <functional>

namespace sbox {

std::size_t TunFlowKeyHash::operator()(const TunFlowKey &key) const noexcept {
  return std::hash<std::uint64_t>{}(
      (static_cast<std::uint64_t>(key.src_ip) << 16) | key.src_port);
}

std::uint16_t TunNat::lookup_or_create(std::uint32_t src_ip,
                                       std::uint16_t src_port,
                                       std::uint32_t dst_ip,
                                       std::uint16_t dst_port) {
  std::lock_guard lock(mutex_);

  TunFlowKey key{src_ip, src_port};
  if (auto it = forward_.find(key); it != forward_.end()) {
    return it->second;
  }

  const auto nat_port = next_port_++;
  forward_[key] = nat_port;
  reverse_[nat_port] = TunNatSession{
      .source_ip = src_ip,
      .source_port = src_port,
      .dest_ip = dst_ip,
      .dest_port = dst_port,
  };

  return nat_port;
}

std::optional<TunNatSession> TunNat::lookup_back(std::uint16_t nat_port) {
  std::lock_guard lock(mutex_);

  if (auto it = reverse_.find(nat_port); it != reverse_.end()) {
    return it->second;
  }

  return std::nullopt;
}

} // namespace sbox