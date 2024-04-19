class ios_base
{
enum seekdir {};
};

template<typename CharT, typename Traits>
class basic_streambuf {};

template<typename CharT, typename Traits>
class basic_istream
{
public:
    typedef typename Traits::int_type 		int_type;
    typedef typename Traits::pos_type 		pos_type;
    typedef typename Traits::off_type 		off_type;

    // Non-standard Types:
    typedef basic_streambuf<CharT, Traits> 		streambuf_type;
    typedef basic_istream<CharT, Traits>	istream_type;
    typedef long int streamsize;

public:

    /// @brief  Base destructor.
    virtual
    ~basic_istream() {}

    //@{
    /**
     *  @brief  Integer arithmetic extractors
     */
    istream_type&
    operator>>(bool& n) {
        sf_overwrite(&n);
        return *this;
    }

    istream_type&
    operator>>(short& n) {
        sf_overwrite(&n);
        sf_set_tainted_short(n);
        return *this;
    }

    istream_type&
    operator>>(unsigned short& n) {
        sf_overwrite(&n);
        sf_set_tainted_ushort(n);
        return *this;
    }

    istream_type&
    operator>>(int& n) {
        sf_overwrite(&n);
        sf_set_tainted_int(n);
        return *this;
    }

    istream_type&
    operator>>(unsigned int& n) {
        sf_overwrite(&n);
        sf_set_tainted_uint(n);
        return *this;
    }

    istream_type&
    operator>>(long& n) {
        sf_overwrite(&n);
        sf_set_tainted_long(n);
        return *this;
    }

    istream_type&
    operator>>(unsigned long& n) {
        sf_overwrite(&n);
        sf_set_tainted_ulong(n);
        return *this;
    }

    istream_type&
    operator>>(long long& n) {
        sf_overwrite(&n);
        sf_set_tainted_longlong(n);
        return *this;
    }

    istream_type&
    operator>>(unsigned long long& n) {
        sf_overwrite(&n);
        sf_set_tainted_ulonglong(n);
        return *this;
    }

    //@}

    //@{
    /**
     *  @brief  Floating point arithmetic extractors
     */
    istream_type&
    operator>>(float& f) {
        sf_overwrite(&f);
        return *this;
    }

    istream_type&
    operator>>(double& f) {
        sf_overwrite(&f);
        return *this;
    }

    istream_type&
    operator>>(long double& f) {
        sf_overwrite(&f);
        return *this;
    }
    //@}

    istream_type&
    operator>>(void*& p) {
        sf_overwrite(&p);
        sf_set_tainted_int((int) p);
        return *this;
    }

    // [27.6.1.3] unformatted input
    /**
     *  @brief  Character counting
     *  @return  The number of characters extracted by the previous
     *           unformatted input function dispatched for this stream.
     */
    streamsize
    gcount() const {
        streamsize n;
        sf_overwrite(&n);
        return n;
    }

    //@{
    /**
     *  @name Unformatted Input Functions
     */

    /**
     *  @brief  Simple extraction.
     */
    int_type
    get() {
        int_type c;
        // TODO: sf_set_tainted_int(c);
        sf_overwrite(&c);
        return c;
    }

    /**
     *  @brief  Simple extraction.
     */
    istream_type&
    get(CharT& c) {
        sf_overwrite(&c);
        // TODO: sf_set_tainted_char(c)
        return *this;
    }

    /**
     *  @brief  Simple multiple-character extraction.
     *  @param  s  Pointer to an array.
     *  @param  n  Maximum number of characters to store in @a s.
     *  @param  delim  A "stop" character.
     *  @return  *this
     */
    istream_type&
    get(CharT* s, streamsize n, CharT delim) {
        sf_overwrite(s);
        sf_set_tainted_buf(s, n, 0);
        sf_null_terminated((char *)s);
        return *this;
    }

    /**
     *  @brief  Simple multiple-character extraction.
     *  @param  s  Pointer to an array.
     *  @param  n  Maximum number of characters to store in @a s.
     *  @return  *this
     */
    istream_type&
    get(CharT* s, streamsize n) {
        sf_overwrite(s);
        sf_set_tainted_buf(s, n, 0);
        sf_null_terminated((char *)s);
        return *this;
    }

    /**
     *  @brief  Extraction into another streambuf.
     *  @param  sb  A streambuf in which to store data.
     *  @param  delim  A "stop" character.
     *  @return  *this
     */
    istream_type&
    get(streambuf_type& sb, CharT delim);

    /**
     *  @brief  Extraction into another streambuf.
     *  @param  sb  A streambuf in which to store data.
     *  @return  *this
     */
    istream_type&
    get(streambuf_type& sb);

    /**
     *  @brief  String extraction.
     *  @param  s  A character array in which to store the data.
     *  @param  n  Maximum number of characters to extract.
     *  @param  __delim  A "stop" character.
     *  @return  *this
     */
    istream_type&
    getline(CharT* s, streamsize n, CharT delim) {
        sf_overwrite(s);
        sf_set_tainted_buf(s, n, 0);
        sf_null_terminated((char *)s);
        return *this;
    }

    /**
     *  @brief  String extraction.
     *  @param  s  A character array in which to store the data.
     *  @param  n  Maximum number of characters to extract.
     *  @return  *this
     */
    istream_type&
    getline(CharT* s, streamsize n) {
        sf_overwrite(s);
        sf_set_tainted_buf(s, n, 0);
        sf_null_terminated((char *)s);
        return *this;
    }

    /**
     *  @brief  Discarding characters
     *  @param  n  Number of characters to discard.
     *  @param  delim  A "stop" character.
     *  @return  *this
     *
     *  NB: Provide three overloads, instead of the single function
     *  (with defaults) mandated by the Standard: this leads to a
     *  better performing implementation, while still conforming to
     *  the Standard.
     */
    istream_type&
    ignore(streamsize n, int_type delim) {
        return *this;
    }

    istream_type&
    ignore(streamsize n) {
        return *this;
    }

    istream_type&
    ignore()  {
        return *this;
    }

    /**
     *  @brief  Looking ahead in the stream
     *  @return  The next character, or eof().
     */
    int_type
    peek() {
        int_type c;
        sf_overwrite(&c);
        // TODO: sf_set_tainted_int(c);
        return c;
    }

    /**
     *  @brief  Extraction without delimiters.
     *  @param  s  A character array.
     *  @param  n  Maximum number of characters to store.
     *  @return  *this
     */
    istream_type&
    read(CharT* s, streamsize n) {
        sf_overwrite(s);
        sf_set_tainted_buf(s, n, 0);
        return *this;
    }

    /**
     *  @brief  Extraction until the buffer is exhausted, but no more.
     *  @param  s  A character array.
     *  @param  n  Maximum number of characters to store.
     *  @return  The number of characters extracted.
     */
    streamsize
    readsome(CharT* s, streamsize n) {
        int read;
        sf_overwrite(s);
        sf_set_tainted_buf(s, n, 0);
        sf_strlen(read, (char*) s);
        return read;
    }

    /**
     *  @brief  Unextracting a single character.
     *  @param  c  The character to push back into the input stream.
     *  @return  *this
     */
    istream_type&
    putback(CharT c);

    /**
     *  @brief  Unextracting the previous character.
     *  @return  *this
     */
    istream_type&
    unget();

    /**
     *  @brief  Synchronizing the stream buffer.
     *  @return  0 on success, -1 on failure
     */
    int
    sync() {
        int ret = sf_range(-1, 0);
        sf_func_success_if(ret, 0);
        return ret;
    }

    /**
     *  @brief  Getting the current read position.
     *  @return  A file position object.
     */
    pos_type
    tellg();

    /**
     *  @brief  Changing the current read position.
     *  @param  pos  A file position object.
     *  @return  *this
     */
    istream_type&
    seekg(pos_type);

    /**
     *  @brief  Changing the current read position.
     *  @param  off  A file offset object.
     *  @param  dir  The direction in which to seek.
     *  @return  *this
     */
    istream_type&
    seekg(off_type, ios_base::seekdir);
    //@}
};

template<typename CharT, typename Traits = char_traits<CharT> >
class basic_istream;

/// Base class for @c char input streams.
typedef basic_istream<char> 		istream;
