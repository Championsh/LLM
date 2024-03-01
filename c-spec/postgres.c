#include "specfunc.h"

typedef void PGconn;

/*
PGconn *PQconnectdbParams(const char **keywords, const char **values, int expand_dbname) {
    sf_password_use(&values);
}


PGconn *PQconnectStartParams(const char **keywords, const char **values, int expand_dbname) {
    sf_password_use(&values);
}
*/

PGconn *PQconnectdb(const char *conninfo) {
    sf_password_use(conninfo);
}

PGconn *PQsetdbLogin(const char *pghost, const char *pgport, const char *pgoptions,
                        const char *pgtty, const char *dbName, const char *login, const char *pwd) {
    sf_password_use(pwd);
}

PGconn *PQconnectStart(const char *conninfo) {
    sf_password_use(conninfo);
}
