#include "specfunc.h"


namespace std {
    template<typename result_type, typename __a, typename __c, typename __m>
    class linear_congruential_engine
    {
    public:
        /**
         * @brief Gets the next random number in the sequence.
         */
        unsigned long
        operator()() {
            unsigned long res;
            sf_overwrite(&res);
            sf_fun_rand();
            sf_set_tainted_ulong(res);
            sf_rand_value(res);
            return res;
        }
    };

    template<typename _UIntType, typename __w,
            typename __n, typename __m, typename __r,
            typename __a, typename __u, typename __d, typename __s,
            typename __b, typename __t,
            typename __c, typename __l, typename __f>
    class mersenne_twister_engine
    {
    public:
        unsigned long
        operator()() {
            unsigned long res;
            sf_overwrite(&res);
            sf_fun_rand();
            sf_set_tainted_ulong(res);
            sf_rand_value(res);
            return res;
        }
    };
    template<typename _UIntType, typename __w, typename __s, typename __r>
    class subtract_with_carry_engine
    {
    public:
        unsigned long
        operator()() {
            unsigned long res;
            sf_overwrite(&res);
            sf_fun_rand();
            sf_set_tainted_ulong(res);
            sf_rand_value(res);
            return res;
        }
    };

    template<typename _RandomNumberEngine, typename __p, typename __r>
    class discard_block_engine
    {
    public:
        unsigned long
        operator()() {
            unsigned long res;
            sf_overwrite(&res);
            sf_fun_rand();
            sf_set_tainted_ulong(res);
            sf_rand_value(res);
            return res;
        }
    };

    template<typename _RandomNumberEngine, typename __w, typename _UIntType>
    class independent_bits_engine
    {
    public:
        unsigned long
        operator()() {
            unsigned long res;
            sf_overwrite(&res);
            sf_fun_rand();
            sf_set_tainted_ulong(res);
            sf_rand_value(res);
            return res;
        }
    };

    template<typename _RandomNumberEngine, typename __k>
    class shuffle_order_engine
    {
    public:
        unsigned long
        operator()() {
            unsigned long res;
            sf_overwrite(&res);
            sf_fun_rand();
            sf_set_tainted_ulong(res);
            sf_rand_value(res);
            return res;
        }
    };
    
    template class linear_congruential_engine<__svace_template_type00,
                                              __svace_template_int01,
                                              __svace_template_int02,
                                              __svace_template_int03>;

    template class mersenne_twister_engine<__svace_template_type00,
                                           __svace_template_int01,
                                           __svace_template_int02,
                                           __svace_template_int03,
                                           __svace_template_int04,
                                           __svace_template_int05,
                                           __svace_template_int06,
                                           __svace_template_int07,
                                           __svace_template_int08,
                                           __svace_template_int09,
                                           __svace_template_int10,
                                           __svace_template_int11,
                                           __svace_template_int12,
                                           __svace_template_int13>;

    template class subtract_with_carry_engine<__svace_template_type00,
                                              __svace_template_int01,
                                              __svace_template_int02,
                                              __svace_template_int03>;

    template class discard_block_engine<__svace_template_type00,
                                        __svace_template_int01,
                                        __svace_template_int02>;

    template class independent_bits_engine<__svace_template_type00,
                                           __svace_template_int01,
                                           __svace_template_type02>;

    template class shuffle_order_engine<__svace_template_type00,
                                        __svace_template_int01>;
}
