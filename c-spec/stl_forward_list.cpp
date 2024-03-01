#include "specfunc.h"

#if __cplusplus < 201103L
#define noexcept
#endif

namespace std {
    template<typename E> class initializer_list {
    };

    template<typename Tp, typename Alloc>
    class forward_list
    {
    public:
        template<typename InputIterator>
        void assign(InputIterator first, InputIterator last) {
            sf_bitinit(this);
        }

        void
        assign(size_t n, const Tp& val) {
            sf_bitinit(this);
        }
        void
        assign(std::initializer_list<Tp> il) {
            sf_bitinit(this);
        }

        void
        resize(size_t sz) {
            sf_bitinit(this);
        }

        void
        resize(size_t sz, const Tp& val) {
            sf_bitinit(this);
        }

        void
        clear() noexcept {
            sf_bitinit(this);
        }
    };

    template class forward_list<__svace_template_type00,
                                __svace_template_type01>;
}