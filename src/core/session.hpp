#pragma once
#include "core/address.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace sbox {

struct Session {
  Destination destination;
  std::vector<unsigned char> initial_payload;
};
}; // namespace sbox