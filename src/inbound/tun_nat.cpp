#include "inbound/tun_nat.hpp"

#include <functional>

namespace cppbox {

std::size_t TunFlowKeyHash::operator()(const TunFlowKey &key) const noexcept {
  std::size_t hash = std::hash<std::uint32_t>{}(key.src_ip);

  const auto combine = [&hash](auto value) {
    hash ^= std::hash<decltype(value)>{}(value) + 0x9e3779b9u + (hash << 6) +
            (hash >> 2);
  };

  combine(key.src_port);
  combine(key.dst_ip);
  combine(key.dst_port);
  return hash;
}

std::uint16_t TunNat::lookup_or_create(std::uint32_t src_ip,
                                       std::uint16_t src_port,
                                       std::uint32_t dst_ip,
                                       std::uint16_t dst_port) {
  std::lock_guard lock(mutex_);

  TunFlowKey key{
      .src_ip = src_ip,
      .src_port = src_port,
      .dst_ip = dst_ip,
      .dst_port = dst_port,
  };
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
void TunNat::erase(std::uint16_t nat_port) {
  std::lock_guard lock(mutex_);

  const auto it = reverse_.find(nat_port);
  if (it == reverse_.end()) {
    return;
  }

  forward_.erase(TunFlowKey{
      .src_ip = it->second.source_ip,
      .src_port = it->second.source_port,
  });
  reverse_.erase(it);
}
std::optional<TunNatSession> TunNat::lookup_back(std::uint16_t nat_port) {
  std::lock_guard lock(mutex_);

  if (auto it = reverse_.find(nat_port); it != reverse_.end()) {
    return it->second;
  }

  return std::nullopt;
}

} // namespace cppbox