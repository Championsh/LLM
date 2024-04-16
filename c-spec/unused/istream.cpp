#include "specfunc.h"
#include "char_traits.h"

namespace std {

  #include "istream.h"

  template class basic_istream<__svace_template_type00>;
  
  template<typename _CharT, typename _Traits>
    basic_istream<_CharT, _Traits>&
    operator>>(basic_istream<_CharT, _Traits>& in, _CharT* s) {
      sf_overwrite(s);
      sf_set_tainted(s);
      return in;
    }

  template<class _Traits>
    inline basic_istream<char, _Traits>&
    operator>>(basic_istream<char, _Traits>& in, unsigned char* s)
    { return (in >> reinterpret_cast<char*>(s)); }

  template<class _Traits>
    inline basic_istream<char, _Traits>&
    operator>>(basic_istream<char, _Traits>& in, signed char* s)
    { return (in >> reinterpret_cast<char*>(s)); }


  template basic_istream<__svace_template_type00, __svace_template_type01>&
  operator>>(basic_istream<__svace_template_type00, __svace_template_type01>& in, __svace_template_type00* s);
}