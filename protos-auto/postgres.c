#include "specfunc.h"

typedef void PGconn;

 

PGconn *PQconnectdb(const char *conninfo);

PGconn *PQsetdbLogin(const char *pghost, const char *pgport, const char *pgoptions,
                        const char *pgtty, const char *dbName, const char *login, const char *pwd);

PGconn *PQconnectStart(const char *conninfo);
