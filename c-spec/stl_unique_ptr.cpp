#include "specfunc.h"

#if __cplusplus >= 201103L
namespace std {
    template <typename Tp> struct default_delete{};

    template <typename Tp, typename Dp = default_delete<Tp>>
    class unique_ptr
    {
    public:
        Tp &operator*() const {
            return *ptr;
        }

        Tp *operator->() const {
            return ptr;
        }

        void
        reset(Tp *p = nullptr) {
            sf_escape(p);
            sf_bitinit(this);
        }

        void
        reset(decltype(nullptr) p) {
            sf_bitinit(this);
        }

        template <typename Up, typename = void>
        void
        reset(Up p) noexcept
        {
            sf_escape(p);
            sf_bitinit(this);
        }
    private:
        Tp *ptr;
    };

    template <typename Tp, typename Dp>
    class unique_ptr<Tp[], Dp>
    {
    public:
        Tp &operator[](size_t i) const {
            return ptr[i];
        }

        void
        reset(Tp *p = nullptr) {
            sf_escape(p);
            sf_bitinit(this);
        }

        void
        reset(decltype(nullptr) p) {
            sf_bitinit(this);
        }

        template <typename Up, typename = void>
        void
        reset(Up p) noexcept
        {
            sf_escape(p);
            sf_bitinit(this);
        }
    private:
        Tp *ptr;
    };

    template<typename _Tp>
    struct _MakeUniq
    { typedef unique_ptr<_Tp> __single_object; };

    template<typename _Tp>
    struct _MakeUniq<_Tp[]>
    { typedef unique_ptr<_Tp[]> __array; };

    /// std::make_unique for single objects
    template<typename _Tp, typename... _Args>
    inline typename _MakeUniq<_Tp>::__single_object
    make_unique(_Args&&... __args) {
        sf_no_exception();
        return unique_ptr<_Tp>(); 
    }

    /// std::make_unique for arrays of unknown bound
    template<typename _Tp>
    inline typename _MakeUniq<_Tp>::__array
    make_unique(size_t __num) {
        sf_no_exception();
        return unique_ptr<_Tp>();
    }

    template class unique_ptr<__svace_template_type00,
                              __svace_template_type01>;
    template class unique_ptr<__svace_template_type00[],
                              __svace_template_type01>;
    template void unique_ptr<__svace_template_type00,
                             __svace_template_type01>::reset<>(__svace_template_type02 *);
    
    template void unique_ptr<__svace_template_type00[],
                             __svace_template_type01>::reset<>(__svace_template_type02 *);

    template typename _MakeUniq<__svace_template_type00>::__single_object 
             make_unique<__svace_template_type00, 
                         __svace_template_type01>
            (__svace_template_type01&& __args);
    
    template typename _MakeUniq<__svace_template_type00>::__single_object 
             make_unique<__svace_template_type00, 
                         __svace_template_type01,
                         __svace_template_type02>
            (__svace_template_type01&& args1, 
             __svace_template_type02&& args2);

    template typename _MakeUniq<__svace_template_type00>::__single_object 
             make_unique<__svace_template_type00, 
                         __svace_template_type01,
                         __svace_template_type02,
                         __svace_template_type03>
            (__svace_template_type01&& args1, 
             __svace_template_type02&& args2,
             __svace_template_type03&& args3);

    template typename _MakeUniq<__svace_template_type00>::__single_object 
             make_unique<__svace_template_type00, 
                         __svace_template_type01,
                         __svace_template_type02,
                         __svace_template_type03,
                         __svace_template_type04>
            (__svace_template_type01&& args1, 
             __svace_template_type02&& args2,
             __svace_template_type03&& args3,
             __svace_template_type04&& args4);
    
    template typename _MakeUniq<__svace_template_type00>::__single_object 
             make_unique<__svace_template_type00, 
                         __svace_template_type01,
                         __svace_template_type02,
                         __svace_template_type03,
                         __svace_template_type04,
                         __svace_template_type05>
            (__svace_template_type01&& args1, 
             __svace_template_type02&& args2,
             __svace_template_type03&& args3,
             __svace_template_type04&& args4,
             __svace_template_type05&& args5);

// Well, okay, I should probably do something smarter with variadic templates. 
// Tempates are the work of the devil, that's what they are!

    template typename _MakeUniq<__svace_template_type00[]>::__array 
             make_unique<__svace_template_type00[]>
            (size_t __args);


}
#endif