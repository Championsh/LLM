#include "specfunc.h"

namespace std {
    template<typename Key, typename Compare, typename Alloc>
    class multiset {
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

    template class multiset<__svace_template_type00,
                       __svace_template_type01,
                       __svace_template_type02>;
}