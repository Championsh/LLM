#include "specfunc.h"

/* A record in the user database.  */
struct passwd {
    char *pw_name;        /* Username.  */
    char *pw_passwd;      /* Hashed passphrase, if shadow database
                             not in use (see shadow.h).  */
    uid_t pw_uid;         /* User ID.  */
    gid_t pw_gid;         /* Group ID.  */
    char *pw_gecos;       /* Real name.  */
    char *pw_dir;         /* Home directory.  */
    char *pw_shell;       /* Shell program.  */
};

struct passwd *getpwnam(const char *name) {
    struct passwd *res;
    sf_overwrite(&res);
    sf_set_possible_null(res);
    if (res != NULL) {
        sf_password_set(res->pw_name);
        sf_password_set(res->pw_passwd);
    }
    return res;
}

struct passwd *getpwuid(uid_t uid) {
    struct passwd *res;
    sf_overwrite(&res);
    sf_password_set(res->pw_name);
    sf_password_set(res->pw_passwd);
    return res;
}
