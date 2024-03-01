#include "specfunc.h"

namespace std {

    typedef struct streampos streampos;
    typedef struct mbstate_t mbstate_t;

	template<typename CharT> struct char_traits {
        typedef CharT           char_type;
        typedef unsigned long long   int_type;
        typedef std::streampos  pos_type;
        typedef long            off_type;
        typedef std::mbstate_t  state_type;
	};


    // TODO: Use different types
    template<>
    struct char_traits<__svace_template_type00>
    {
      typedef __svace_template_type00       char_type;
      typedef __svace_template_type01     int_type;
      typedef __svace_template_type02     pos_type;
      typedef __svace_template_type03     off_type;
      typedef __svace_template_type04     state_type;
    };
}