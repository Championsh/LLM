#include "specfunc.h"

//??
#define noexcept 

#define size_type size_t

#define __svace_can_throw_bad_alloc()    sf_could_throw("std::bad_alloc")
#define __svace_can_throw_out_of_range() sf_could_throw("std::out_of_range")
#define __svace_can_throw_length_error() sf_could_throw_pedantic("std::length_error")

namespace __gnu_cxx {
	template <typename T1, typename T2> 
	struct __normal_iterator {
	};
}

namespace std {
	template<typename T> struct char_traits {
	};
	template<typename T> struct allocator {
	};
	
	#include "istream.h"
	#include "stl-string.h"

	template class basic_string<__svace_template_type00>;
	
	namespace __cxx11 {
		#include "stl-string.h"

		template class basic_string<__svace_template_type00>;
	} 

	template<typename _CharT, typename _Traits, typename _Alloc>
	basic_istream<_CharT, _Traits>&
	operator>>(basic_istream<_CharT, _Traits>& in,
	basic_string<_CharT, _Traits, _Alloc>& str){
		sf_overwrite(&str);
		sf_set_tainted(&str);
		return in;
	}
	//I cannot see any way to implement it as a single template:(
	template<typename _CharT, typename _Traits, typename _Alloc>
	basic_istream<_CharT, _Traits>&
	operator>>(basic_istream<_CharT, _Traits>& in,
	__cxx11::basic_string<_CharT, _Traits, _Alloc>& str){
		sf_overwrite(&str);
		sf_set_tainted(&str);
		return in;
	}

	template basic_istream<__svace_template_type00>& operator>>(basic_istream<__svace_template_type00>&, basic_string<__svace_template_type00>&);
	template basic_istream<__svace_template_type00>& operator>>(basic_istream<__svace_template_type00>&, __cxx11::basic_string<__svace_template_type00>&);
}

