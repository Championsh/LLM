#include "specfunc.h"

void Tcl_Panic(const char *format, ...) {
    char c = *format;
    sf_use_format(format);
    sf_terminate_path();
}

// void Tcl_PanicVA(format, argList)

// void Tcl_SetPanicProc(panicProc)

void panic(const char *format, ...) {
    char c = *format;
    sf_use_format(format);
    sf_terminate_path();
}

// void panicVA(format, argList)
