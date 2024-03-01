#include "specfunc.h"

namespace std {
	#include "stl-allocator.h"

	template struct allocator<char>;
	template struct allocator<wchar_t>;
}

