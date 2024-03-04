#include "specfunc.h"

#define _Xconst const
#define Bool int
# ifdef LONG64
typedef long INT64;
typedef int INT32;
# else
typedef long INT32;
# endif

typedef char *String;

typedef unsigned long XID;
typedef XID Window;
typedef unsigned long Atom;
typedef unsigned int Cardinal;

#ifdef CRAY
typedef long        Boolean;
typedef char*       XtArgVal;
typedef long        XtEnum;
#else
typedef char        Boolean;
typedef long        XtArgVal;
typedef unsigned char   XtEnum;
#endif

struct _WidgetRec;
typedef struct _WidgetRec *Widget;
struct _XDisplay;
typedef struct _XDisplay Display;
typedef struct ; XHostAddress;

typedef struct ; Arg, *ArgList;

typedef struct ; XF86VidModeModeLine;

typedef struct ; XIAnyClassInfo;

typedef struct ; XIDeviceInfo;

struct Colormap;


int XAddHost(Display* dpy, XHostAddress* host)
;

int XRemoveHost(Display* dpy, XHostAddress* host)
;

int XChangeProperty(Display *dpy, Window w, Atom property,
                    Atom type, int format, int mode,
                    _Xconst unsigned char * data, int nelements)
;

Bool XF86VidModeModModeLine(Display *dpy, int screen, XF86VidModeModeLine *modeline)
;

void XtGetValues(Widget w, ArgList args, Cardinal num_args);

XIDeviceInfo* XIQueryDevice(Display *display,
                             int deviceid,
                             int *ndevices_return);

XIFreeDeviceInfo(XIDeviceInfo *info);

struct Colormap *XListInstalledColormaps(Display *display, Window w, int *num_return);

XFree(void *data);
