#include "specfunc.h"

namespace std {
    class bad_alloc {
        public: bad_alloc() throw();
    };

    struct nothrow_t {} nothrow;
}

void *operator new(size_t size) throw (std::bad_alloc) {
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, NEW_CATEGORY);
    sf_not_null(ptr);
    sf_set_buf_size(ptr, size);
    sf_lib_arg_type(ptr, "NewCategory");
    

    sf_could_throw("std::bad_alloc");

    return ptr;
}

void *operator new[](size_t size) throw (std::bad_alloc) {
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, NEW_ARRAY_CATEGORY);
    sf_raw_new(ptr);
    sf_not_null(ptr);
    sf_set_buf_size(ptr, size);
    sf_lib_arg_type(ptr, "NewArrayCategory");

    sf_could_throw("std::bad_alloc");

    return ptr;
}

void *operator new(size_t size, const std::nothrow_t &) throw () {
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, NEW_CATEGORY);
    sf_set_buf_size(ptr, size);
    sf_set_alloc_possible_null(ptr, size);
    sf_lib_arg_type(ptr, "NewCategory");

    return ptr;
}

void *operator new[](size_t size, const std::nothrow_t &) throw () {
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, NEW_ARRAY_CATEGORY);
    sf_set_buf_size(ptr, size);
    sf_set_alloc_possible_null(ptr, size);
    sf_lib_arg_type(ptr, "NewArrayCategory");

    return ptr;
}


void operator delete(void *ptr) throw () {
    //ptr may be null.
    //sf_overwrite(ptr);
    sf_delete(ptr, NEW_CATEGORY);
    sf_lib_arg_type(ptr, "NewCategory");
}

void operator delete[](void *ptr) throw () {
    //ptr may be null.
    //sf_overwrite(ptr);
    sf_delete(ptr, NEW_ARRAY_CATEGORY);
    sf_lib_arg_type(ptr, "NewArrayCategory");
}


// Versions for CoreCLR

struct NoThrow { int x; };

void *operator new(size_t size, const NoThrow &) throw () {
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, NEW_CATEGORY);
    sf_set_buf_size(ptr, size);
    sf_set_alloc_possible_null(ptr, size);
    sf_lib_arg_type(ptr, "NewCategory");

    return ptr;
}

void *operator new[](size_t size, const NoThrow &) throw () {
    sf_set_trusted_sink_int(size);

    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_new(ptr, NEW_ARRAY_CATEGORY);
    sf_set_buf_size(ptr, size);
    sf_set_alloc_possible_null(ptr, size);
    sf_lib_arg_type(ptr, "NewArrayCategory");

    return ptr;
}
