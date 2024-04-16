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
typedef struct {
        int family;
        int length;
        char *address;
} XHostAddress;

typedef struct {
    String  name;
    XtArgVal    value;
} Arg, *ArgList;

typedef struct {
    unsigned short      hdisplay;
    unsigned short      hsyncstart;
    unsigned short      hsyncend;
    unsigned short      htotal;
    unsigned short      hskew;
    unsigned short      vdisplay;
    unsigned short      vsyncstart;
    unsigned short      vsyncend;
    unsigned short      vtotal;
    unsigned int        flags;
    int                 privsize;
#if defined(__cplusplus) || defined(c_plusplus)
    /* private is a C++ reserved word */
    INT32               *c_private;
#else
    INT32               *private;
#endif
} XF86VidModeModeLine;

typedef struct {
    int         type;
    int         sourceid;
} XIAnyClassInfo;

typedef struct {
    int                 deviceid;
    char                *name;
    int                 use;
    int                 attachment;
    Bool                enabled;
    int                 num_classes;
    XIAnyClassInfo      **classes;
} XIDeviceInfo;

struct Colormap;


int XAddHost(Display* dpy, XHostAddress* host)
{
  sf_use(host);
}

int XRemoveHost(Display* dpy, XHostAddress* host)
{
  sf_use(host);
}

int XChangeProperty(Display *dpy, Window w, Atom property,
                    Atom type, int format, int mode,
                    _Xconst unsigned char * data, int nelements)
{
  sf_use(data); 
}

Bool XF86VidModeModModeLine(Display *dpy, int screen, XF86VidModeModeLine *modeline)
{
  sf_use(modeline);
}

void XtGetValues(Widget w, ArgList args, Cardinal num_args) {
  sf_bitinit_subelements(args);
}

XIDeviceInfo* XIQueryDevice(Display *display,
                             int deviceid,
                             int *ndevices_return) {
    XIDeviceInfo *res;
    sf_overwrite(&res);
    sf_overwrite(res);
	//sf_uncontrolled_value(res);
    //sf_set_possible_null(res);
    sf_bitinit(ndevices_return);
    sf_handle_acquire(res, X11_DEVICE);
    return res;
}

XIFreeDeviceInfo(XIDeviceInfo *info) {
	sf_must_not_be_release(info);

    sf_overwrite(info);
    sf_handle_release(info, X11_DEVICE);
}

struct Colormap *XListInstalledColormaps(Display *display, Window w, int *num_return) {
    struct Colormap *res;
    sf_overwrite(&res);
    sf_overwrite(res);
	//sf_uncontrolled_value(res);
    //sf_set_possible_null(res);
    sf_handle_acquire(res, X11_CATEGORY);
    return res;
}

XFree(void *data) {
	sf_must_not_be_release(data);

    sf_overwrite(data);
    sf_handle_release(data, X11_CATEGORY);
}
