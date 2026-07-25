#pragma once

#include "core/net.hpp"
#include <atomic>
#include <boost/asio/signal_set.hpp>
#include <functional>
#include <mutex>
#include <vector>

namespace sbox {

class Shutdown {
public:
  explicit Shutdown(asio::io_context &io);

  void start();
  void stop();
  void on_stop(std::function<void()> callback);

private:
  void request_stop();
  void run_callbacks_once();

  asio::io_context &io_;
  asio::signal_set signals_;
  std::atomic_bool stopping_{false};
  std::mutex callbacks_mutex_;
  std::vector<std::function<void()>> callbacks_;
};

} // namespace sbox