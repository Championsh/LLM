#include "specfunc.h"

#if __cplusplus < 201103L
#define noexcept
#endif

namespace std {
    template<typename Key, typename Tp, typename Hash,
             typename Pred, typename Alloc>
    class unordered_map {
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

    template<typename Key, typename Tp, typename Hash,
             typename Pred, typename Alloc>
    class unordered_multimap
    {
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

    template class unordered_map<__svace_template_type00,
                                 __svace_template_type01,
                                 __svace_template_type02,
                                 __svace_template_type03,
                                 __svace_template_type04>;

    template class unordered_multimap<__svace_template_type00,
                                      __svace_template_type01,
                                      __svace_template_type02,
                                      __svace_template_type03,
                                      __svace_template_type04>;
}