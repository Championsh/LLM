#include "specfunc.h"

#ifndef _UTSNAME_SYSNAME_LENGTH
# define _UTSNAME_LENGTH 65
#endif

#ifndef _UTSNAME_SYSNAME_LENGTH
# define _UTSNAME_SYSNAME_LENGTH _UTSNAME_LENGTH
#endif
#ifndef _UTSNAME_NODENAME_LENGTH
# define _UTSNAME_NODENAME_LENGTH _UTSNAME_LENGTH
#endif
#ifndef _UTSNAME_RELEASE_LENGTH
# define _UTSNAME_RELEASE_LENGTH _UTSNAME_LENGTH
#endif
#ifndef _UTSNAME_VERSION_LENGTH
# define _UTSNAME_VERSION_LENGTH _UTSNAME_LENGTH
#endif
#ifndef _UTSNAME_MACHINE_LENGTH
# define _UTSNAME_MACHINE_LENGTH _UTSNAME_LENGTH
#endif

/* Structure describing the system and machine.  */
struct utsname
  {
    /* Name of the implementation of the operating system.  */
    char sysname[_UTSNAME_SYSNAME_LENGTH];
    /* Name of this node on the network.  */
    char nodename[_UTSNAME_NODENAME_LENGTH];
    /* Current release level of this implementation.  */
    char release[_UTSNAME_RELEASE_LENGTH];
    /* Current version level of this release.  */
    char version[_UTSNAME_VERSION_LENGTH];
    /* Name of the hardware type the system is running on.  */
    char machine[_UTSNAME_MACHINE_LENGTH];
#if _UTSNAME_DOMAIN_LENGTH - 0
    /* Name of the domain of this node on the network.  */
# ifdef __USE_GNU
    char domainname[_UTSNAME_DOMAIN_LENGTH];
# else
    char __domainname[_UTSNAME_DOMAIN_LENGTH];
# endif
#endif
  };
#ifdef __USE_MISC
/* Note that SVID assumes all members have the same size.  */
# define SYS_NMLN  _UTSNAME_LENGTH
#endif

/* Put information about the system in NAME.  */
int uname (struct utsname *name) {
    sf_bitinit(name);
    sf_password_set(name->sysname);
    sf_password_set(name->nodename);
    sf_password_set(name->release);
    sf_password_set(name->version);
    sf_password_set(name->machine);

    int ret;
    sf_overwrite(&ret);
    return ret;
}
