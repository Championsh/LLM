#include "specfunc.h"
#include "basetypes.h"

// Exception handling

typedef void __guard;

namespace std {

#define EXCEPTION(name) void __throw_##name() { sf_could_throw("std::" #name); }
#define EXCEPTION_ONE_PARAM(name) void __throw_##name(const char*) { sf_could_throw("std::" #name); }

EXCEPTION(bad_exception   )
EXCEPTION(bad_alloc       )
EXCEPTION(bad_cast        )
EXCEPTION(bad_typeid      )

EXCEPTION_ONE_PARAM(logic_error     )
EXCEPTION_ONE_PARAM(domain_error    )
EXCEPTION_ONE_PARAM(invalid_argument)
//EXCEPTION_ONE_PARAM(length_error    )
EXCEPTION_ONE_PARAM(out_of_range    )
EXCEPTION_ONE_PARAM(runtime_error   )
EXCEPTION_ONE_PARAM(range_error     )
EXCEPTION_ONE_PARAM(overflow_error  )
EXCEPTION_ONE_PARAM(underflow_error )

#undef EXCEPTION

void __throw_length_error(const char *s) { sf_could_throw_pedantic("std::length_error"); }

void __throw_ios_failure(const char *s) { sf_could_throw("std::ios_base::failure"); }

/*
  void
  __throw_system_error(int __i __attribute__((unused)))
  { _GLIBCXX_THROW_OR_ABORT(system_error(error_code(__i, generic_category()))); }

  void
  __throw_future_error(int __i __attribute__((unused)))
  { _GLIBCXX_THROW_OR_ABORT(future_error(make_error_code(future_errc(__i)))); }

  void
  __throw_bad_function_call()
  { _GLIBCXX_THROW_OR_ABORT(bad_function_call()); }

  void
  __throw_regex_error(regex_constants::error_type __ecode
      __attribute__((unused)))
  { _GLIBCXX_THROW_OR_ABORT(regex_error(__ecode)); }

}
*/

} // end of namespace std

//LLVM internal functions:
extern "C" void __cxa_bad_cast() {
    sf_could_throw("std::bad_cast");
}

extern "C" void __cxa_bad_typeid() {
    sf_could_throw("std::bad_typeid");
}

namespace __cxxabiv1 {
    extern "C" {
        int __cxa_guard_acquire(__guard *x) {
            sf_overwrite(x);
            return *(int *)x;
        }

        void __cxa_guard_release(__guard *x) {
            sf_overwrite(x);
        }

        void __cxa_guard_abort(__guard *x) {
            sf_overwrite(x);
        }
    }
}

extern "C" void __clang_call_terminate(char *p) {
    sf_terminate_path();
}


extern "C" void *__dynamic_cast(const void *src_ptr, const __class_type_info* src_type, const __class_type_info* dst_type, ptrdiff_t src2dst) {
    void *res;
    sf_overwrite(&res);
    sf_pure((int)(intptr_t)res, src_ptr, src_type, dst_type, src2dst);
    return res;
}

