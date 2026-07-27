#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>

namespace sbox {
using error_code = boost::system::error_code;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;
namespace ssl = asio::ssl;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
}; // namespace sbox