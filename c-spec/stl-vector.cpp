#include "specfunc.h"

#if __cplusplus < 201103L
    #define noexcept
#endif

namespace std {
    template<typename T> struct allocator {
	};
    template<typename E> class initializer_list {
    };

    template <typename T, typename Allocator = std::allocator<T> >
    class vector {
        void** svace_alloc(size_t n) {
            void **ptr;
            sf_overwrite(&ptr);
            sf_heap(ptr);
            sf_set_buf_size(ptr, n);
            return ptr;
        }

        void* svace_some_value() {
            void *ptr;
            sf_overwrite(&ptr);
            sf_overwrite(ptr);
            return ptr;
        }

        void **svace_ptr;
    public:
        struct iterator {};
        struct const_iterator {};
        vector();

        explicit
        vector(size_t n, const Allocator& a = Allocator()) {
            this->svace_ptr = svace_alloc(n);
        }

        vector(size_t n, const T& value,
               const Allocator& a = Allocator()) {
            this->svace_ptr = svace_alloc(n);
        }

        vector(const vector& x);

        vector& operator=(const vector& x);
        
#if __cplusplus >= 201103L
        vector(vector&& x) noexcept;
        
        vector& operator=(vector&& x);
#endif

        void assign(size_t n, const T& val) {
            sf_bitinit(this);
            svace_ptr[n] = svace_some_value();
        }

        template<typename InputIterator>
        void assign(InputIterator first, InputIterator last) {
            sf_bitinit(this);
        }

        void assign(initializer_list<T> l) {
            sf_bitinit(this);
        }

        size_t size() const noexcept;

        void resize(size_t new_size) {
            sf_bitinit(this);
        };

        void resize(size_t new_size, const T& x) {
            sf_bitinit(this);
        }

        size_t capacity() const noexcept;

        bool empty() const noexcept;

        void reserve(size_t n);

        T& operator[](size_t n) noexcept {
            sf_use_only(n);
            void* ptr = svace_ptr[n];
            return at(n);
        }

        const T& operator[](size_t n) const noexcept {
            sf_use_only(n);
            void* ptr = svace_ptr[n];
            return at(n);
        }

        T& at(size_t n);

        const T& at(size_t n) const;

        T& front() noexcept;

        const T& front() const noexcept;

        T& back() noexcept;

        const T& back() const noexcept;

        T* data() noexcept;

        const T* data() const noexcept;

        void push_back(const T& x);

#if __cplusplus >= 201103L
        void push_back(T&& x);
#endif

        //template<typename... _Args>
        //reference emplace_back(_Args&&... __args); // __cplusplus > 201402L
        //void emplace_back(_Args&&... __args); //__cplusplus <= 201402L

        void pop_back() noexcept;

        //template<typename... _Args>
        //iterator emplace(const_iterator __position, _Args&&... __args)

        //different cpp versions:
        iterator insert(const_iterator position, const T& x);
        iterator insert(iterator position, const T& __x);

        iterator insert(const_iterator position, initializer_list<T> l);
        
        //different cpp versions:
        iterator insert(const_iterator position, size_t n, const T& x);
        void insert(iterator position, size_t n, const T& x);

        //different cpp versions:
        template<typename InputIterator>
	    iterator insert(const_iterator position, InputIterator first, InputIterator last);
        template<typename InputIterator>
        void insert(iterator position, InputIterator first, InputIterator last);

        //different cpp versions:
        iterator erase(const_iterator position);
        iterator erase(iterator position);

        //different cpp versions:
        iterator erase(const_iterator first, const_iterator last);
        iterator erase(iterator first, iterator last);

        //std::swap calls this
        void swap(vector& __x) noexcept;

        void clear() noexcept {
            sf_bitinit(this);
        }
    };

    template<typename T, typename Allocator>
    inline void swap(vector<T, Allocator>& x, vector<T, Allocator>& y) noexcept
    {
        x.swap(y);
    }

    template class vector<__svace_template_type00>;

    template void swap(vector<__svace_template_type00>& x,
                              vector<__svace_template_type00>& y);
}
