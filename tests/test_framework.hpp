// Minimal deterministic test framework.
//
// No timeouts, no watchdogs, no framework-provided clocks: a test either
// completes or it hangs, and a hanging test is a defect. Failures are recorded
// with file and line and the run continues so that one broken expectation does
// not hide the rest.
#ifndef MPF_TEST_FRAMEWORK_HPP
#define MPF_TEST_FRAMEWORK_HPP

#include <atomic>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace mpf_test {

using TestFunction = void (*)();

struct TestCase {
  std::string name;
  TestFunction function = nullptr;
};

[[nodiscard]] std::vector<TestCase>& registry();
void register_test(const char* name, TestFunction function);

struct Registrar {
  Registrar(const char* name, TestFunction function) { register_test(name, function); }
};

// Thread safe: tests are allowed to record expectations from worker threads.
struct RunState {
  std::string current_test;
  std::atomic<std::uint64_t> checks{0};
  std::atomic<std::uint64_t> failures{0};
  std::mutex failure_mutex;
  std::vector<std::string> failure_messages;
  std::atomic<bool> current_test_failed{false};
};

// Comparison indirection. Comparing two captured locals directly in an "if"
// makes MSVC constant-fold the controlling expression and emit C4127 for
// literal comparisons; routing through a function keeps the check honest
// without suppressing a diagnostic.
template <class Left, class Right>
[[nodiscard]] inline bool values_equal(const Left& left, const Right& right) {
  return left == right;
}

[[nodiscard]] RunState& state();
void report_failure(const char* file, int line, const std::string& message);
[[nodiscard]] int run_all(int argc, char** argv);

// Deterministic pseudo random generator: identical sequences on every platform
// and every run for a given seed.
class Random {
 public:
  explicit Random(std::uint64_t seed) noexcept : state_(seed == 0 ? 0x9E3779B97F4A7C15ULL : seed) {}

  [[nodiscard]] std::uint64_t next() noexcept {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  [[nodiscard]] std::uint64_t below(std::uint64_t bound) noexcept {
    return bound == 0 ? 0 : next() % bound;
  }

  [[nodiscard]] std::uint64_t seed() const noexcept { return state_; }

 private:
  std::uint64_t state_;
};

}  // namespace mpf_test

#define MPF_TEST(test_name)                                                        \
  static void test_name();                                                         \
  static ::mpf_test::Registrar mpf_registrar_##test_name(#test_name, &test_name);  \
  static void test_name()

#define MPF_CHECK(condition)                                                       \
  do {                                                                             \
    ++::mpf_test::state().checks;                                                  \
    if (!(condition)) {                                                            \
      ::mpf_test::report_failure(__FILE__, __LINE__, "CHECK failed: " #condition); \
    }                                                                              \
  } while (false)

// The operands are captured BY VALUE on purpose. Binding a reference would
// dangle whenever the operand is a subobject of a temporary, for example
// *some_optional(), because the temporary dies at the end of the declaration
// statement and reference lifetime extension does not reach subobjects.
#define MPF_CHECK_EQ(actual, expected)                                             \
  do {                                                                             \
    ++::mpf_test::state().checks;                                                  \
    const auto mpf_actual = (actual);                                              \
    const auto mpf_expected = (expected);                                          \
    if (!::mpf_test::values_equal(mpf_actual, mpf_expected)) {                     \
      std::ostringstream mpf_stream;                                               \
      mpf_stream << "CHECK_EQ failed: " #actual " == " #expected;                  \
      ::mpf_test::report_failure(__FILE__, __LINE__, mpf_stream.str());            \
    }                                                                              \
  } while (false)

#define MPF_CHECK_MSG(condition, message)                                          \
  do {                                                                             \
    ++::mpf_test::state().checks;                                                  \
    if (!(condition)) {                                                            \
      std::ostringstream mpf_stream;                                               \
      mpf_stream << "CHECK failed: " #condition " -- " << message;                 \
      ::mpf_test::report_failure(__FILE__, __LINE__, mpf_stream.str());            \
    }                                                                              \
  } while (false)

#define MPF_REQUIRE_MSG(condition, message)                                        \
  do {                                                                             \
    ++::mpf_test::state().checks;                                                  \
    if (!(condition)) {                                                            \
      std::ostringstream mpf_stream;                                               \
      mpf_stream << "REQUIRE failed: " #condition " -- " << message;               \
      ::mpf_test::report_failure(__FILE__, __LINE__, mpf_stream.str());            \
      return;                                                                      \
    }                                                                              \
  } while (false)

#define MPF_REQUIRE(condition)                                                     \
  do {                                                                             \
    ++::mpf_test::state().checks;                                                  \
    if (!(condition)) {                                                            \
      ::mpf_test::report_failure(__FILE__, __LINE__, "REQUIRE failed: " #condition); \
      return;                                                                      \
    }                                                                              \
  } while (false)

#endif  // MPF_TEST_FRAMEWORK_HPP
