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

TunNat::TunNat(std::size_t max_sessions) : max_sessions_(max_sessions) {}

void TunNat::touch_locked(std::uint16_t nat_port) {
  const auto it = std::find(lru_.begin(), lru_.end(), nat_port);
  if (it != lru_.end()) {
    lru_.erase(it);
  }
  lru_.push_back(nat_port);
}

std::optional<std::uint16_t> TunNat::evict_one_locked() {
  while (!lru_.empty()) {
    const auto nat_port = lru_.front();
    lru_.pop_front();

    const auto it = reverse_.find(nat_port);
    if (it == reverse_.end()) {
      continue;
    }

    forward_.erase(it->second);
    reverse_.erase(it);
    return nat_port;
  }

  return std::nullopt;
}

TunNatLookupResult TunNat::lookup_or_create(std::uint32_t src_ip,
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
    touch_locked(it->second);
    return TunNatLookupResult{.nat_port = it->second};
  }

  std::optional<std::uint16_t> evicted_nat_port;
  if (max_sessions_ != 0 && reverse_.size() >= max_sessions_) {
    evicted_nat_port = evict_one_locked();
  }

  const auto nat_port = allocate_port_locked();
  forward_[key] = nat_port;
  reverse_[nat_port] = key;
  touch_locked(nat_port);

  return TunNatLookupResult{
      .nat_port = nat_port,
      .evicted_nat_port = evicted_nat_port,
  };
}
std::uint16_t TunNat::allocate_port_locked() noexcept {
  for (;;) {
    const auto nat_port = next_port_++;
    if (nat_port == 0) {
      next_port_ = 10000;
      continue;
    }
    if (!reverse_.contains(nat_port)) {
      return nat_port;
    }
  }
}

void TunNat::erase(std::uint16_t nat_port) {
  std::lock_guard lock(mutex_);

  const auto it = reverse_.find(nat_port);
  if (it == reverse_.end()) {
    return;
  }

  forward_.erase(it->second);
  reverse_.erase(it);
  const auto lru_it = std::find(lru_.begin(), lru_.end(), nat_port);
  if (lru_it != lru_.end()) {
    lru_.erase(lru_it);
  }
}
std::optional<TunFlowKey> TunNat::lookup_back(std::uint16_t nat_port) {
  std::lock_guard lock(mutex_);

  if (auto it = reverse_.find(nat_port); it != reverse_.end()) {
    return it->second;
  }

  return std::nullopt;
}

} // namespace cppbox