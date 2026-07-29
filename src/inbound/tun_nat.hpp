#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace cppbox {

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
  std::uint16_t lookup_or_create(std::uint32_t src_ip, std::uint16_t src_port,
                                 std::uint32_t dst_ip, std::uint16_t dst_port);

  std::optional<TunFlowKey> lookup_back(std::uint16_t nat_port);
  void erase(std::uint16_t nat_port);

private:
  std::mutex mutex_;
  std::uint16_t next_port_{10000};

  std::unordered_map<TunFlowKey, std::uint16_t, TunFlowKeyHash> forward_;
  std::unordered_map<std::uint16_t, TunFlowKey> reverse_;
};

} // namespace cppbox