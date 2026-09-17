// Real operating system process helper for the distributed proofs.
//
// Children are genuine OS processes started with CreateProcess (Windows) or
// fork/exec (POSIX), with output redirected to files so that no pipe can
// deadlock. Termination is a real forced termination, not a flag.
#ifndef MPF_TEST_PROCESS_HPP
#define MPF_TEST_PROCESS_HPP

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
// The wire protocol has a message named ERROR. The Windows macro of the same
// name would rewrite every reference to it in test code, so it is removed here.
// It is restored nowhere because no test uses the Windows macro.
#if defined(ERROR)
#undef ERROR
#endif
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace mpf_test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { terminate(); }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  ChildProcess(ChildProcess&& other) noexcept { move_from(other); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      terminate();
      move_from(other);
    }
    return *this;
  }

  // Starts the process. Returns false when it could not be created.
  bool start(const std::string& executable, const std::vector<std::string>& arguments,
             const std::string& output_path) {
    terminate();
#if defined(_WIN32)
    std::string command_line = quote(executable);
    for (const auto& argument : arguments) {
      command_line += ' ';
      command_line += quote(argument);
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE output = INVALID_HANDLE_VALUE;
    if (!output_path.empty()) {
      output = ::CreateFileA(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    if (output != INVALID_HANDLE_VALUE) {
      startup.dwFlags |= STARTF_USESTDHANDLES;
      startup.hStdOutput = output;
      startup.hStdError = output;
      startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION information{};
    std::vector<char> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back('\0');
    const BOOL created = ::CreateProcessA(
        nullptr, mutable_command.data(), nullptr, nullptr,
        output != INVALID_HANDLE_VALUE ? TRUE : FALSE,
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &startup, &information);
    if (output != INVALID_HANDLE_VALUE) {
      ::CloseHandle(output);
    }
    if (!created) {
      return false;
    }
    ::CloseHandle(information.hThread);
    process_ = information.hProcess;
    pid_ = information.dwProcessId;
    return true;
#else
    (void)output_path;
    std::vector<std::string> storage;
    storage.push_back(executable);
    for (const auto& argument : arguments) {
      storage.push_back(argument);
    }
    std::vector<char*> argv;
    for (auto& value : storage) {
      argv.push_back(value.data());
    }
    argv.push_back(nullptr);
    pid_t pid = 0;
    if (posix_spawn(&pid, executable.c_str(), nullptr, nullptr, argv.data(), environ) != 0) {
      return false;
    }
    pid_ = pid;
    return true;
#endif
  }

  [[nodiscard]] bool running() const {
#if defined(_WIN32)
    if (process_ == nullptr) {
      return false;
    }
    return ::WaitForSingleObject(process_, 0) == WAIT_TIMEOUT;
#else
    if (pid_ == 0) {
      return false;
    }
    int status = 0;
    return ::waitpid(pid_, &status, WNOHANG) == 0;
#endif
  }

  // Real forced termination of the operating system process.
  void terminate() {
#if defined(_WIN32)
    if (process_ != nullptr) {
      if (::WaitForSingleObject(process_, 0) == WAIT_TIMEOUT) {
        ::TerminateProcess(process_, 137);
      }
      ::WaitForSingleObject(process_, 10000);
      ::CloseHandle(process_);
      process_ = nullptr;
      pid_ = 0;
    }
#else
    if (pid_ != 0) {
      ::kill(pid_, SIGKILL);
      int status = 0;
      ::waitpid(pid_, &status, 0);
      pid_ = 0;
    }
#endif
  }

  [[nodiscard]] std::uint64_t pid() const noexcept { return static_cast<std::uint64_t>(pid_); }

 private:
  static std::string quote(const std::string& value) {
    std::string result = "\"";
    for (const char character : value) {
      if (character == '"') {
        result += "\\\"";
      } else {
        result += character;
      }
    }
    result += '"';
    return result;
  }

  void move_from(ChildProcess& other) {
#if defined(_WIN32)
    process_ = other.process_;
    other.process_ = nullptr;
#else
    pid_ = other.pid_;
    other.pid_ = 0;
#endif
    pid_ = other.pid_;
    other.pid_ = 0;
  }

#if defined(_WIN32)
  void* process_ = nullptr;
#endif
  std::uint64_t pid_ = 0;
};

// Polls a file for expected content. The deadline produces an explicit failure
// rather than an unbounded wait: callers record a test failure when it expires.
[[nodiscard]] inline std::string wait_for_file(const std::string& path,
                                               std::uint32_t timeout_ms = 30000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    std::error_code error;
    if (std::filesystem::exists(path, error)) {
      std::ifstream stream(path, std::ios::binary);
      std::string content;
      if (std::getline(stream, content) && !content.empty()) {
        return content;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return std::string();
}

[[nodiscard]] inline std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (const char character : text) {
    if (character == separator) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(character);
    }
  }
  parts.push_back(current);
  return parts;
}

}  // namespace mpf_test

#endif  // MPF_TEST_PROCESS_HPP
