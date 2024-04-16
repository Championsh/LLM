    template<typename Tp, typename Alloc>
    class list {
    public:
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
        assign(size_t n, const Tp& val) {
            sf_bitinit(this);
        }

        template<typename InputIterator>
        void
	    assign(InputIterator first, InputIterator last) {
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
        bool
        empty() const {
            int x;
            sf_overwrite(&x);
            return x;
        }
    };