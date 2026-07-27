#include "core/shutdown.hpp"
#include "core/log.hpp"
#include <csignal>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace cppbox {
namespace {

#ifdef _WIN32
Shutdown *g_shutdown = nullptr;

BOOL WINAPI console_handler(DWORD signal) {
  switch (signal) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    if (g_shutdown != nullptr) {
      g_shutdown->stop();
    }
    return TRUE;
  default:
    return FALSE;
  }
}
#endif

} // namespace

Shutdown::Shutdown(asio::io_context &io)
    : io_(io), signals_(io, SIGINT, SIGTERM) {
#ifdef _WIN32
  g_shutdown = this;
#endif
}

void Shutdown::start() {
#ifdef _WIN32
  SetConsoleCtrlHandler(console_handler, TRUE);
#endif

  signals_.async_wait([this](const error_code &ec, int) {
    if (!ec) {
      request_stop();
    }
  });
}

void Shutdown::stop() {
  asio::post(io_, [this] { request_stop(); });
}

void Shutdown::on_stop(std::function<void()> callback) {
  std::lock_guard lock(callbacks_mutex_);
  callbacks_.push_back(std::move(callback));
}

void Shutdown::request_stop() {
  if (stopping_.exchange(true)) {
    return;
  }

  log_info("stopping");
  run_callbacks_once();

#ifdef _WIN32
  SetConsoleCtrlHandler(console_handler, FALSE);
  g_shutdown = nullptr;
#endif

  signals_.cancel();
  io_.stop();
}

void Shutdown::run_callbacks_once() {
  std::vector<std::function<void()>> callbacks;

  {
    std::lock_guard lock(callbacks_mutex_);
    callbacks.swap(callbacks_);
  }

  for (auto &callback : callbacks) {
    try {
      callback();
    } catch (const std::exception &e) {
      log_error(std::string("shutdown callback failed: ") + e.what());
    }
  }
}

} // namespace cppbox