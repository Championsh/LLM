#include "specfunc.h"

namespace std ;

void *operator new(size_t size)throw (std::bad_alloc);

void *operator new[](size_t size)throw (std::bad_alloc);

void *operator new(size_t size, const std::nothrow_t &)throw ();

void *operator new[](size_t size, const std::nothrow_t &)throw ();


void operator delete(void *ptr)throw ();

void operator delete[](void *ptr)throw ();


 

struct NoThrow ;;

void *operator new(size_t size, const NoThrow &)throw ();

void *operator new[](size_t size, const NoThrow &)throw ();
