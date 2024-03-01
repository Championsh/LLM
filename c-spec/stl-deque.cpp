#include "specfunc.h"

namespace std {
    template<class E>
    class initializer_list {};

    template<typename Tp, typename Alloc>
    class deque
    {
    public:
        void
        assign(size_t n, const Tp& val) {
            sf_bitinit(this);
        }

        template<typename InputIterator>
        void
        assign(InputIterator first, InputIterator last) {
            sf_bitinit(this);
        }
        void
        assign(initializer_list<Tp> l) {
            sf_bitinit(this);
        }

        void
        resize(size_t new_size) {
            sf_bitinit(this);
        }

        void
        resize(size_t new_size, const Tp& x) {
            sf_bitinit(this);
        }

        void
        resize(size_t new_size, Tp x = Tp()) {
            sf_bitinit(this);
        }

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

    template class deque<__svace_template_type00,
                         __svace_template_type01>;
}