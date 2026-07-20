#pragma once
#include "core/net.hpp"
#include <boost/asio/awaitable.hpp>
#include <vector>
namespace sbox {
class Stream{
    public:
    virtual ~Stream()=default;
    virtual asio::awaitable<std::vector<unsigned char>> read()=0;
    virtual asio::awaitable<void> write(const std::vector<unsigned char> &bytes) = 0;
    virtual void close()=0;
};
}