#include "specfunc.h"

class PCMem
{
private:
        PCMem(void) {}
public:
      static void Copy(void* dest, const void* source, unsigned long count);
};

void PCMem::Copy(void* dest, const void* source, unsigned long size) {
    char d1 = *(char*)dest;
    char d2 = *(char*)source;
    sf_bitinit(dest);
    sf_buf_copy(dest, source);
    sf_buf_size_limit(source, size);
    sf_buf_size_limit_read(source, size);
    sf_buf_stop_at_null(const_cast<void *>(static_cast<const void *>(source)));
}

