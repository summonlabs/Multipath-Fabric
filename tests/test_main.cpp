#include "test_framework.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>

namespace mpf_test {
namespace {

RunState g_state;

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

void register_test(const char* name, TestFunction function) {
  registry().push_back(TestCase{name, function});
}

RunState& state() { return g_state; }

void report_failure(const char* file, int line, const std::string& message) {
  g_state.failures.fetch_add(1);
  g_state.current_test_failed.store(true);
  std::ostringstream stream;
  stream << "FAIL " << g_state.current_test << " " << file << ':' << line << ": " << message;
  std::lock_guard<std::mutex> guard(g_state.failure_mutex);
  g_state.failure_messages.push_back(stream.str());
}

int run_all(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string token(argv[i]);
    if (token.rfind("--filter=", 0) == 0) {
      filter = token.substr(9);
    } else if (token == "--list") {
      list_only = true;
    }
  }
  std::vector<TestCase> selected;
  for (const auto& test : registry()) {
    if (filter.empty() || test.name.find(filter) != std::string::npos) {
      selected.push_back(test);
    }
  }
  std::sort(selected.begin(), selected.end(),
            [](const TestCase& a, const TestCase& b) { return a.name < b.name; });
  if (list_only) {
    for (const auto& test : selected) {
      std::cout << test.name << '\n';
    }
    return 0;
  }
  if (selected.empty()) {
    std::cout << "no tests selected" << '\n';
    return 1;
  }
  std::uint64_t passed = 0;
  for (const auto& test : selected) {
    g_state.current_test = test.name;
    g_state.current_test_failed.store(false);
    test.function();
    if (g_state.current_test_failed.load()) {
      std::cout << "not ok  " << test.name << '\n';
    } else {
      ++passed;
      std::cout << "ok      " << test.name << '\n';
    }
    std::cout.flush();
  }
  for (const auto& message : g_state.failure_messages) {
    std::cout << message << '\n';
  }
  std::cout << "---" << '\n'
            << "tests=" << selected.size() << " passed=" << passed
            << " failed=" << (selected.size() - passed) << " checks=" << g_state.checks.load()
            << " failures=" << g_state.failures.load() << '\n';
  return g_state.failures.load() == 0 ? 0 : 1;
}

}  // namespace mpf_test

int main(int argc, char** argv) { return mpf_test::run_all(argc, argv); }
