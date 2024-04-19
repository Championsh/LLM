#include "specfunc.h"

#if __cplusplus >= 201103L
namespace std {
    // Define operator* and operator-> for shared_ptr<T>.
    template<typename Tp, typename Lp,
    typename is_array, typename is_void>
    class __shared_ptr_access
    {
    public:
        Tp&
        operator*() const noexcept {
            return *ptr;
        }

        Tp*
        operator->() const noexcept {
            return ptr;
        }

        Tp &operator[](long i) const {
            return ptr[i];
        }
    private:
        Tp *ptr;
    };

    template <typename Tp, typename Dp>
    class __shared_ptr
    {
    public:
        Tp &operator[](size_t i) const {
            return ptr[i];
        }

        Tp &operator*() const {
            return *ptr;
        }

        Tp *operator->() const {
            return ptr;
        }

        void
        reset(Tp *p) {
            sf_escape(p);
            sf_bitinit(this);
        }

        void
        reset() {
            sf_bitinit(this);
        }
    private:
        Tp *ptr;
    };

    template class __shared_ptr_access<__svace_template_type00,
                                       __svace_template_int01,
                                       __svace_template_bool02,
                                       __svace_template_bool03>;

    template class __shared_ptr<__svace_template_type00,
                              __svace_template_int01>;
}
#endif