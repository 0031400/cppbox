#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>

namespace sbox {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using error_code = boost::system::error_code;
namespace ssl = asio::ssl;
namespace beast = boost::beast;
}; // namespace sbox