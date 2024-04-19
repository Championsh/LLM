#include "specfunc.h"

int _CrtDbgReport(
   int reportType,
   const char *filename,
   int linenumber,
   const char *moduleName,
   const char *format,
   ...
) {
    sf_terminate_path();
}

int _CrtDbgReportW(
   int reportType,
   const wchar_t *filename,
   int linenumber,
   const wchar_t *moduleName,
   const wchar_t *format,
   ...
) {
    sf_terminate_path();
}
