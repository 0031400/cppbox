#pragma once
#include "core/session.hpp"
#include <string>
#include <vector>
namespace sbox {
struct VlessConfig {
  std::string uuid;
};
class VlessProtocol {
public:
  explicit VlessProtocol(VlessConfig config);
  std::vector<unsigned char> build_request(const Destination &dst) const;
  static void strip_response_header(std::vector<unsigned char> &bytes);

private:
  VlessConfig config_;
};
}; // namespace sbox