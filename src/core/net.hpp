#pragma once
#include <boost/asio.hpp>
namespace sbox {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using error_code = boost::system::error_code;
}; // namespace sbox