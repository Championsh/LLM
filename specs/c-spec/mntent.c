#include "specfunc.h"

FILE *setmntent(const char *filename, const char *type) {
    sf_tocttou_access(filename);
}

// struct mntent *getmntent(FILE *fp);
// int addmntent(FILE *fp, const struct mntent *mnt);
// int endmntent(FILE *fp);
// char *hasmntopt(const struct mntent *mnt, const char *opt);

/* GNU extension */
// struct mntent *getmntent_r(FILE *fp, struct mntent *mntbuf,
//               char *buf, int buflen);
