// Specifications for the C++ <exception>
#include "specfunc.h"

// namespace std {

typedef void (*terminate_handler)();
typedef void (*unexpected_handler)();

// void unexpected(); [[noreturn]]
// This function is called when dynamic exception specification is violated
extern "C" void _ZSt10unexpectedv(void)
{
  // TODO: also calls handler std::unexpected_handler
  sf_terminate_path();
}

// void terminate(); [[noreturn]]
// This function is called when exception handling fails
extern "C" void _ZSt9terminatev(void)
{
  // TODO: also calls handler std::terminate_handler
  sf_terminate_path();
}

// Checks if exception handling is currently in progress
// bool uncaught_exception();

// Creates an std::exception_ptr from an exception object (C++11)
// template<class E> exception_ptr make_exception_ptr(E e);

// Captures the current exception in a std::exception_ptr (C++11)
// exception_ptr current_exception();

// Throws the exception from an std::exception_ptr (C++11)
// void rethrow_exception(exception_ptr p); [[noreturn]]

// Throws its argument with std::nested_exception mixed in (C++11)
// template <class T> void throw_with_nested(T&& t); [[noreturn]]

// Throws the exception from a std::nested_exception (C++11)
// template <class E> void rethrow_if_nested(const E& e);

// Obtains the current terminate_handler (C++11)
// terminate_handler get_terminate();

// Changes the function to be called by std::terminate
// terminate_handler set_terminate(terminate_handler f);

// Obtains the current unexpected_handler (C++11)
// unexpected_handler get_unexpected();

// Changes the function to be called by std::unexpected
// unexpected_handler set_unexpected(unexpected_handler f);

