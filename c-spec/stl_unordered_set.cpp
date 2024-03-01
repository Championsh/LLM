#include "specfunc.h"

#if __cplusplus < 201103L
#define noexcept
#endif

namespace std {
    template<typename Value, typename Hash, typename Pred,
             typename Alloc>
    class unordered_set
    {
    public:
        void
        clear() noexcept {
            sf_bitinit(this);
        }

        size_t
        size() const {
            int x;
            sf_overwrite(&x);
            return x;
        }
    };

    template<typename Value, typename Hash, typename Pred,
             typename Alloc>
    class unordered_multiset
    {
    public:
        void
        clear() noexcept {
            sf_bitinit(this);
        }

        size_t
        size() const {
            int x;
            sf_overwrite(&x);
            return x;
        }
    };

    template class unordered_set <__svace_template_type00,
                                  __svace_template_type01,
                                  __svace_template_type02,
                                  __svace_template_type03>;

    template class unordered_multiset <__svace_template_type00,
                                       __svace_template_type01,
                                       __svace_template_type02,
                                       __svace_template_type03>;
}