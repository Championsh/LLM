#include <specfunc.h>

namespace std {
    template<typename CharT, typename Traits>
    class basic_ostream {
        typedef basic_ostream<CharT, Traits>    ostream_type;

        ostream_type& operator<<(long n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(unsigned long n){
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(bool n){
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(short n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(unsigned short n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(int n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(unsigned int n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(long long n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(unsigned long long n) {
            sf_data_leak((void *)n);
            return *this;
        }

        ostream_type& operator<<(double f) {
            //sf_data_leak((void *)f);
            return *this;
        }

        ostream_type& operator<<(float f) {
            //sf_data_leak((void *)f);
            return *this;
        }

        ostream_type& operator<<(long double f) {
            //sf_data_leak((void *)f);
            return *this;
        }
    };

    template<typename CharT, typename Traits>
    inline basic_ostream<CharT, Traits>&
    operator<<(basic_ostream<CharT, Traits>& out, const CharT* s)
    {
        sf_data_leak((void*)s);
        return out;
    }

    template<typename CharT, typename Traits>
    basic_ostream<CharT, Traits> &
    operator<<(basic_ostream<CharT, Traits>& out, const char* s) {
        sf_data_leak((void*)s);
        return out;
    }

    // Partial specializations
    template<typename Traits>
    inline basic_ostream<char, Traits>&
    operator<<(basic_ostream<char, Traits>& out, const char* s) {
        sf_data_leak((void*)s);
        return out;
    }

    // Signed and unsigned
    template<typename Traits>
    inline basic_ostream<char, Traits>&
    operator<<(basic_ostream<char, Traits>& out, const signed char* s)
    { return (out << reinterpret_cast<const char*>(s)); }

    template<typename Traits>
    inline basic_ostream<char, Traits> &
    operator<<(basic_ostream<char, Traits>& out, const unsigned char* s)
    { return (out << reinterpret_cast<const char*>(s)); }

    

    template basic_ostream<__svace_template_type00, __svace_template_type01>&
    operator<<(basic_ostream<__svace_template_type00, __svace_template_type01>& out, const __svace_template_type00* s);

    template basic_ostream<__svace_template_type00, __svace_template_type01>&
    operator<<(basic_ostream<__svace_template_type00, __svace_template_type01>& out, const char* s);

    template basic_ostream<char, __svace_template_type00>&
    operator<<(basic_ostream<char, __svace_template_type00>& out, const char* s);
    
    template basic_ostream<char, __svace_template_type00>&
    operator<<(basic_ostream<char, __svace_template_type00>& out, const signed char* s);

    template basic_ostream<char, __svace_template_type00>&
    operator<<(basic_ostream<char, __svace_template_type00>& out, const unsigned char* s);


    template class basic_ostream<__svace_template_type00, __svace_template_type01>;

}
