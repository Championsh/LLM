#include "specfunc.h"

 
#define noexcept 

#define size_type size_t

#define __svace_can_throw_bad_alloc()   sf_could_throw("std::bad_alloc")
#define __svace_can_throw_out_of_range()sf_could_throw("std::out_of_range")
#define __svace_can_throw_length_error()sf_could_throw_pedantic("std::length_error")

namespace __gnu_cxx ;

namespace std ;

