#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace cppbox {
struct TunNatLookupResult {
  std::uint16_t nat_port{};
  std::optional<std::uint16_t> evicted_nat_port;
};
struct TunFlowKey {
  std::uint32_t src_ip{};
  std::uint16_t src_port{};
  std::uint32_t dst_ip{};
  std::uint16_t dst_port{};

  bool operator==(const TunFlowKey &) const = default;
};

struct TunFlowKeyHash {
  std::size_t operator()(const TunFlowKey &key) const noexcept;
};

class TunNat {
public:
  explicit TunNat(std::size_t max_sessions = 0);

  TunNatLookupResult lookup_or_create(std::uint32_t src_ip,
                                      std::uint16_t src_port,
                                      std::uint32_t dst_ip,
                                      std::uint16_t dst_port);

  std::optional<TunFlowKey> lookup_back(std::uint16_t nat_port);
  void erase(std::uint16_t nat_port);

private:
  std::uint16_t allocate_port_locked() noexcept;
  void touch_locked(std::uint16_t nat_port);
  std::optional<std::uint16_t> evict_one_locked();

  std::mutex mutex_;
  std::uint16_t next_port_{10000};
  std::size_t max_sessions_{};

  std::unordered_map<TunFlowKey, std::uint16_t, TunFlowKeyHash> forward_;
  std::unordered_map<std::uint16_t, TunFlowKey> reverse_;
  std::deque<std::uint16_t> lru_;
};
} // namespace cppbox