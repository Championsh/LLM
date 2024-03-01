class bad_alloc {
	public: bad_alloc() throw();
};
class length_error {
	public: length_error() throw();
};
class out_of_range {
	public: out_of_range() throw();
};

template<typename charT, typename Traits = char_traits<charT>, typename allocator_type = allocator<charT> > 
class basic_string {
public:
	struct iterator {
    	};
	struct const_iterator {
	};

	//damn it!
	typedef __gnu_cxx::__normal_iterator<charT *, basic_string> gnu_iterator;
	typedef __gnu_cxx::__normal_iterator<const charT *, basic_string> const_gnu_iterator;

	basic_string() {
	}

	basic_string(const basic_string& str, size_type pos, size_type len, const allocator_type& alloc) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_out_of_range();
	}

	basic_string(const charT* s, const allocator_type& alloc) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	basic_string(const charT* s, size_type n, const allocator_type& alloc) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	basic_string(size_type n, charT c, const allocator_type& alloc) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	basic_string(const basic_string& str, size_type pos, size_type len) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_out_of_range();
	}

	basic_string(const charT* s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	basic_string(const charT* s, size_type n) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	basic_string(size_type n, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	~basic_string() {
	    //sf_bind_ptr1("string_dtor", &me);
//	    sf_partial_specification();
		sf_string_dtor(this);
	}

	const charT* c_str() const {
	    const charT*res;
	    sf_overwrite(&res);

	//    sf_bind_ptr_with_res("c_str", &me);
	    sf_string_c_str_result((void *) res, (void *) this);
	    return res;
	}

	size_t find (const basic_string& str, size_t pos = 0) const noexcept {
		size_t res;
		sf_overwrite(&res);
		sf_set_possible_negative(res);
		return res;
	}

	size_t find (const char* s, size_t pos = 0) const {
		size_t res;
		sf_overwrite(&res);
		sf_set_possible_negative(res);
		return res;
	}

	size_t find (const charT* s, size_t pos, size_type n) const{
		size_t res;
		sf_overwrite(&res);
		sf_set_possible_negative(res);
		return res;
	}

	size_t find (charT c, size_t pos = 0) const noexcept{
		size_t res;
		sf_overwrite(&res);
		sf_set_possible_negative(res);
		return res;
	}

	void resize (size_type n)  {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	void reserve (size_type n) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

    basic_string& operator= (const charT* s) {
        return *this;
    }

    basic_string& operator= (const basic_string& s) {
        return *this;
    }

    basic_string& operator= (charT c ) {
        return *this;
    }

	basic_string& operator+= (const charT* s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& operator+= (const basic_string& s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& operator+= (charT c ) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	void push_back (charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	basic_string& append(const basic_string& add, size_type subpos, size_type sublen) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& append (const basic_string& str) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& append (const charT *s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& append (const charT* s, size_t n)  {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& append (size_t n, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& assign (const basic_string& str, size_t subpos, size_t sublen) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_out_of_range();
		sf_bitinit(this);
	    return *this;
	}

	basic_string& assign (const charT* s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
		sf_bitinit(this);
	    return *this;
	}

	basic_string& assign (const charT* s, size_t n) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
		sf_bitinit(this);
	    return *this;
	}

	basic_string& assign (size_t n, charT c)  {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
		sf_bitinit(this);
	    return *this;
	}


	basic_string& insert (size_t pos, const basic_string& str) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& insert (size_t pos, const basic_string& str,
		                size_t subpos, size_t sublen) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& insert (size_t pos, const charT* s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& insert (size_t pos, const charT* s, size_t n) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& insert (size_t pos, size_t n, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	void insert (iterator p,     size_t n, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}


	void insert (gnu_iterator p,     size_t n, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	}

	iterator insert (iterator p, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    void* res;
	    sf_overwrite(&res);
	    return *(iterator*)res;
	}

	gnu_iterator insert (gnu_iterator p, charT c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    void* res;
	    sf_overwrite(&res);
	    return *(gnu_iterator*)res;
	}

	charT& at (size_t pos)  {
	    __svace_can_throw_out_of_range();

	    charT* res;
	    sf_overwrite(&res);
	    return *res;
	}

	const charT& at (size_t pos) const {
	    __svace_can_throw_out_of_range();

	    charT* res;
	    sf_overwrite(&res);
	    return *res;
	}

	basic_string& erase (size_t pos, size_t len)  {
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	size_t copy (charT* s, size_t len, size_t pos) const {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_out_of_range();

	    size_t res;
	    sf_overwrite(&res);
	    return res;
	}

	basic_string substr (size_t pos, size_t len) const {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_out_of_range();

	    basic_string res;
	    sf_overwrite(&res);
	    return res;
	}

	basic_string& replace (size_t pos, size_t len, const basic_string& str) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& replace (iterator i1,   iterator i2,   const basic_string& str) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (gnu_iterator i1,   gnu_iterator i2,   const basic_string& str) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (size_t pos, size_t len, const basic_string& str,
		                 size_t subpos, size_t sublen){
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& replace (size_t pos, size_t len, const char* s) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& replace (iterator i1,   iterator i2,   const char* s){
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (gnu_iterator i1,   gnu_iterator i2,   const char* s){
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (size_t pos, size_t len, const char* s, size_t n){
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& replace (iterator i1,   iterator i2,   const char* s, size_t n) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (gnu_iterator i1,   gnu_iterator i2,   const char* s, size_t n) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (size_t pos, size_t len, size_t n, char c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();
	    __svace_can_throw_out_of_range();

	    return *this;
	}

	basic_string& replace (iterator i1,   iterator i2,   size_t n, char c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	basic_string& replace (gnu_iterator i1,   gnu_iterator i2,   size_t n, char c) {
	    __svace_can_throw_bad_alloc();
	    __svace_can_throw_length_error();

	    return *this;
	}

	int compare (size_t pos, size_t len, const basic_string& str) const {
	    __svace_can_throw_out_of_range();

	    int res;
	    sf_overwrite(&res);
	    return res < 0 ? -1 : (res > 0 ? 1 : 0);
	}

	int compare (size_t pos, size_t len, const basic_string& str, size_t subpos, size_t sublen) const  {
	    __svace_can_throw_out_of_range();

	    int res;
	    sf_overwrite(&res);
	    return res < 0 ? -1 : (res > 0 ? 1 : 0);
	}

	int compare (size_t pos, size_t len, const charT* s) const  {
	    __svace_can_throw_out_of_range();

	    int res;
	    sf_overwrite(&res);
	    return res < 0 ? -1 : (res > 0 ? 1 : 0);
	}

	int compare (size_t pos, size_t len, const charT* s, size_t n) const {
	    __svace_can_throw_out_of_range();

	    int res;
	    sf_overwrite(&res);
	    return res < 0 ? -1 : (res > 0 ? 1 : 0);
	}

	//???
	size_t length(const char *s) const {
	    char d1 = *s;

	    size_t res;
	    sf_overwrite(&res);
	    sf_strlen(res, s);
	    return res;
	}

	size_t length() const {
            size_t res;
            sf_overwrite(&res);
            return res;
	}
	
	size_t size() const {
		size_t res;
		sf_overwrite(&res);
		return res;
	}
	
	void clear() {
		sf_bitinit(this);
	}
};

