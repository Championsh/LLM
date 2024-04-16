#include "specfunc.h"

typedef wchar_t OLECHAR;
typedef OLECHAR* BSTR;
typedef const char* LPCSTR;

BSTR SysAllocString(const OLECHAR *psz) {
    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);

    sf_copy_string(ptr, psz);
    return ptr; 
}

BSTR SysAllocStringByteLen(LPCSTR psz, unsigned int len) {
    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, len);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_buf_copy(ptr, psz);
//  sf_buf_size_limit(psz, len+1);
    sf_buf_stop_at_null(psz);
    return ptr; 
}

BSTR SysAllocStringLen(const OLECHAR *pch, unsigned int len) {
    sf_set_trusted_sink_ptr(len);    

    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, len);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_buf_copy(ptr, pch);
//  sf_buf_size_limit(pch, len+1);
    return ptr; 
}

int SysReAllocString(BSTR *pbstr, const OLECHAR *psz) {
    //sf_not_null(pbstr); - incorrect use of it

    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_copy_string(ptr, psz);
    
    sf_escape(pbstr);
    int res;
	sf_overwrite(&res);
    //sf_not_acquire_if_eq(ptr, res, 0);
    sf_not_acquire_if_less(ptr, res, 1);
    return res; // Returns True if the string is successfully reallocated, or False if insufficient memory exists.
}

int SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, unsigned int len) {
    //sf_not_null(pbstr); - incorrect use

    sf_set_trusted_sink_ptr(len);
    
    BSTR ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_uncontrolled_ptr(ptr);
    sf_set_alloc_possible_null(ptr, len);
    sf_new(ptr, BSTR_ALLOC_CATEGORY);
    sf_buf_copy(ptr, psz);
    sf_buf_size_limit(psz, len);

    sf_overwrite(pbstr);
    sf_delete(pbstr, BSTR_ALLOC_CATEGORY);
    
    int res;
	sf_overwrite(&res);
    //sf_not_acquire_if_eq(ptr, res, 0);
    sf_not_acquire_if_less(ptr, res, 1);
    return res; // Returns True if the string is successfully reallocated, or False if insufficient memory exists.
}

void SysFreeString(BSTR bstrString) {
    sf_set_possible_null(bstrString); 
    sf_overwrite(bstrString);
    sf_delete(bstrString, BSTR_ALLOC_CATEGORY);    
}

unsigned int SysStringLen(BSTR bstr) {
// empty spec
}
