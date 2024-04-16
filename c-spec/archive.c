#include "specfunc.h"

struct archive;

ssize_t
archive_read_data(struct archive *archive, void *buff, size_t len) {
    sf_bitinit(buff);

    sf_overwrite(buff);
    sf_set_tainted(buff);
    sf_set_possible_nnts(buff);
    sf_buf_size_limit(buff, len);

    ssize_t x;
    sf_overwrite(&x);
    sf_set_possible_negative(x);
    sf_uncontrolled_value(x);
    sf_set_possible_equals(x, len);

    sf_assert_cond(x, "<=", len);
    sf_set_errno_if(x, sf_cond_range("==", -1));
    sf_no_errno_if(x, sf_cond_range(">=", 0));
    sf_buf_fill(x, buff);
    return x;
}
