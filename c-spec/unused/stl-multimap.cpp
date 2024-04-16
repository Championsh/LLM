#include "specfunc.h"

namespace std {
    template <typename Key, typename Tp, typename Compare, typename Alloc>
    class multimap {
    public:
        void
        clear() {
            sf_bitinit(this);
        }
        
        size_t
        size() const {
            int x;
            sf_overwrite(&x);
            return x;
        }
    };

    template class multimap<__svace_template_type00,
                            __svace_template_type01,
                            __svace_template_type02,
                            __svace_template_type03>;
}