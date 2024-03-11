#include "specfunc.h"

 
 
#define EMPTY_FUNC_SPEC_T(rtype, type1, func)\
  rtype func(type1 x);
#define EMPTY_FUNC_SPEC(type, func)EMPTY_FUNC_SPEC_T(type, type, func)
#define EMPTY_FUNC_SPEC2_T(rtype, type1, type2, func)\
  rtype func(type1 x, type2 y);
#define EMPTY_FUNC_SPEC2(type, func)EMPTY_FUNC_SPEC2_T(type, type, type, func)
#define EMPTY_FUNC_SPEC3_T(rtype, type1, type2, type3, func)\
  rtype func(type1 x, type2 y, type3 z);
#define EMPTY_FUNC_SPEC3(type, func)EMPTY_FUNC_SPEC3_T(type, type, type, type, func)


EMPTY_FUNC_SPEC(double, acos)
EMPTY_FUNC_SPEC(float, acosf)
EMPTY_FUNC_SPEC(long double, acosl)

EMPTY_FUNC_SPEC(double, acosh)
EMPTY_FUNC_SPEC(float, acoshf)
EMPTY_FUNC_SPEC(long double, acoshl)

EMPTY_FUNC_SPEC(double, asin)
EMPTY_FUNC_SPEC(float, asinf)
EMPTY_FUNC_SPEC(long double, asinl)

EMPTY_FUNC_SPEC(double, asinh)
EMPTY_FUNC_SPEC(float, asinhf)
EMPTY_FUNC_SPEC(long double, asinhl)

EMPTY_FUNC_SPEC(double, atan)
EMPTY_FUNC_SPEC(float, atanf)
EMPTY_FUNC_SPEC(long double, atanl)

EMPTY_FUNC_SPEC(double, atanh)
EMPTY_FUNC_SPEC(float, atanhf)
EMPTY_FUNC_SPEC(long double, atanhl)

EMPTY_FUNC_SPEC2(double, atan2)
EMPTY_FUNC_SPEC2(float, atan2f)
EMPTY_FUNC_SPEC2(long double, atan2l)

EMPTY_FUNC_SPEC(double, cos)
EMPTY_FUNC_SPEC(float, cosf)
EMPTY_FUNC_SPEC(long double, cosl)

EMPTY_FUNC_SPEC(double, cosh)
EMPTY_FUNC_SPEC(float, coshf)
EMPTY_FUNC_SPEC(long double, coshl)

EMPTY_FUNC_SPEC(double, sin)
EMPTY_FUNC_SPEC(float, sinf)
EMPTY_FUNC_SPEC(long double, sinl)

EMPTY_FUNC_SPEC(double, sinh)
EMPTY_FUNC_SPEC(float, sinhf)
EMPTY_FUNC_SPEC(long double, sinhl)

EMPTY_FUNC_SPEC(double, tan)
EMPTY_FUNC_SPEC(float, tanf)
EMPTY_FUNC_SPEC(long double, tanl)

EMPTY_FUNC_SPEC(double, tanh)
EMPTY_FUNC_SPEC(float, tanhf)
EMPTY_FUNC_SPEC(long double, tanhl)


EMPTY_FUNC_SPEC(double, exp)
EMPTY_FUNC_SPEC(float, expf)
EMPTY_FUNC_SPEC(long double, expl)

EMPTY_FUNC_SPEC(double, exp2)
EMPTY_FUNC_SPEC(float, exp2f)
EMPTY_FUNC_SPEC(long double, exp2l)

EMPTY_FUNC_SPEC(double, expm1)
EMPTY_FUNC_SPEC(float, expm1f)
EMPTY_FUNC_SPEC(long double, expm1l)

EMPTY_FUNC_SPEC(double, log)
EMPTY_FUNC_SPEC(float, logf)
EMPTY_FUNC_SPEC(long double, logl)

EMPTY_FUNC_SPEC(double, log2)
EMPTY_FUNC_SPEC(float, log2f)
EMPTY_FUNC_SPEC(long double, log2l)

EMPTY_FUNC_SPEC(double, log10)
EMPTY_FUNC_SPEC(float, log10f)
EMPTY_FUNC_SPEC(long double, log10l)

EMPTY_FUNC_SPEC(double, log1p)
EMPTY_FUNC_SPEC(float, log1pf)
EMPTY_FUNC_SPEC(long double, log1pl)

EMPTY_FUNC_SPEC(double, logb)
EMPTY_FUNC_SPEC(float, logbf)
EMPTY_FUNC_SPEC(long double, logbl)

EMPTY_FUNC_SPEC_T(int, double, ilogb)
EMPTY_FUNC_SPEC_T(int, float, ilogbf)
EMPTY_FUNC_SPEC_T(int, long double, ilogbl)


EMPTY_FUNC_SPEC2(double, pow)
EMPTY_FUNC_SPEC2(float, powf)
EMPTY_FUNC_SPEC2(long double, powl)

EMPTY_FUNC_SPEC(double, sqrt)
EMPTY_FUNC_SPEC(float, sqrtf)
EMPTY_FUNC_SPEC(long double, sqrtl)

EMPTY_FUNC_SPEC(double, cbrt)
EMPTY_FUNC_SPEC(float, cbrtf)
EMPTY_FUNC_SPEC(long double, cbrtl)

EMPTY_FUNC_SPEC2(double, hypot)
EMPTY_FUNC_SPEC2(float, hypotf)
EMPTY_FUNC_SPEC2(long double, hypotl)


EMPTY_FUNC_SPEC(double, floor)
EMPTY_FUNC_SPEC(float, floorf)
EMPTY_FUNC_SPEC(long double, floorl)

EMPTY_FUNC_SPEC(double, ceil)
EMPTY_FUNC_SPEC(float, ceilf)
EMPTY_FUNC_SPEC(long double, ceill)

EMPTY_FUNC_SPEC(double, nearbyint)
EMPTY_FUNC_SPEC(float, nearbyintf)
EMPTY_FUNC_SPEC(long double, nearbyintl)

EMPTY_FUNC_SPEC(double, rint)
EMPTY_FUNC_SPEC(float, rintf)
EMPTY_FUNC_SPEC(long double, rintl)

EMPTY_FUNC_SPEC(double, round)
EMPTY_FUNC_SPEC(float, roundf)
EMPTY_FUNC_SPEC(long double, roundl)

EMPTY_FUNC_SPEC(double, trunc)
EMPTY_FUNC_SPEC(float, truncf)
EMPTY_FUNC_SPEC(long double, truncl)

EMPTY_FUNC_SPEC_T(long int, double, lrint)
EMPTY_FUNC_SPEC_T(long int, float, lrintf)
EMPTY_FUNC_SPEC_T(long int, long double, lrintl)

EMPTY_FUNC_SPEC_T(long long int, double, llrint)
EMPTY_FUNC_SPEC_T(long long int, float, llrintf)
EMPTY_FUNC_SPEC_T(long long int, long double, llrintl)

EMPTY_FUNC_SPEC_T(long int, double, lround)
EMPTY_FUNC_SPEC_T(long int, float, lroundf)
EMPTY_FUNC_SPEC_T(long int, long double, lroundl)

EMPTY_FUNC_SPEC_T(long long int, double, llround)
EMPTY_FUNC_SPEC_T(long long int, float, llroundf)
EMPTY_FUNC_SPEC_T(long long int, long double, llroundl)


EMPTY_FUNC_SPEC(double, fabs)
EMPTY_FUNC_SPEC(float, fabsf)
EMPTY_FUNC_SPEC(long double, fabsl)

EMPTY_FUNC_SPEC(double, nextafter)
EMPTY_FUNC_SPEC(float, nextafterf)
EMPTY_FUNC_SPEC(long double, nextafterl)

EMPTY_FUNC_SPEC(double, nexttoward)
EMPTY_FUNC_SPEC(float, nexttowardf)
EMPTY_FUNC_SPEC(long double, nexttowardl)


EMPTY_FUNC_SPEC2(double, fmod)
EMPTY_FUNC_SPEC2(float, fmodf)
EMPTY_FUNC_SPEC2(long double, fmodl)

EMPTY_FUNC_SPEC2(double, remainder)
EMPTY_FUNC_SPEC2(float, remainderf)
EMPTY_FUNC_SPEC2(long double, remainderl)

EMPTY_FUNC_SPEC2(double, drem)
EMPTY_FUNC_SPEC2(float, dremf)
EMPTY_FUNC_SPEC2(long double, dreml)

EMPTY_FUNC_SPEC2(double, fdim)
EMPTY_FUNC_SPEC2(float, fdimf)
EMPTY_FUNC_SPEC2(long double, fdiml)

EMPTY_FUNC_SPEC3(double, fma)
EMPTY_FUNC_SPEC3(float, fmaf)
EMPTY_FUNC_SPEC3(long double, fmal)

EMPTY_FUNC_SPEC2(double, fmax)
EMPTY_FUNC_SPEC2(float, fmaxf)
EMPTY_FUNC_SPEC2(long double, fmaxl)

EMPTY_FUNC_SPEC2(double, fmin)
EMPTY_FUNC_SPEC2(float, fminf)
EMPTY_FUNC_SPEC2(long double, fminl)

double frexp(double x, int* y);

EMPTY_FUNC_SPEC2(long double, frexpl)

EMPTY_FUNC_SPEC2_T(double, double, int, ldexp)
EMPTY_FUNC_SPEC2_T(float, float, int, ldexpf)
EMPTY_FUNC_SPEC2_T(long double, long double, int, ldexpl)

EMPTY_FUNC_SPEC2(double, lgamma)
EMPTY_FUNC_SPEC2(float, lgammaf)
EMPTY_FUNC_SPEC2(long double, lgammal)

EMPTY_FUNC_SPEC2(double, tgamma)
EMPTY_FUNC_SPEC2(float, tgammaf)
EMPTY_FUNC_SPEC2(long double, tgammal)

EMPTY_FUNC_SPEC2(double, copysign)
EMPTY_FUNC_SPEC2(float, copysignf)
EMPTY_FUNC_SPEC2(long double, copysignl)

EMPTY_FUNC_SPEC(double, erf)
EMPTY_FUNC_SPEC(float, erff)
EMPTY_FUNC_SPEC(long double, erfl)

EMPTY_FUNC_SPEC(double, erfc)
EMPTY_FUNC_SPEC(float, erfcf)
EMPTY_FUNC_SPEC(long double, erfcl)

EMPTY_FUNC_SPEC2_T(double, double, long int, scalbln)
EMPTY_FUNC_SPEC2_T(float, float, long int, scalblnf)
EMPTY_FUNC_SPEC2_T(long double, long double, long int, scalblnl)

EMPTY_FUNC_SPEC2_T(double, double, int, scalbn)
EMPTY_FUNC_SPEC2_T(float, float, int, scalbnf)
EMPTY_FUNC_SPEC2_T(long double, long double, int, scalbnl)


double modf(double x, double *iptr);

float modff(float x, float *iptr);

long double modfl(long double x, long double *iptr);

double lgamma_r(double x, int *signp);

float lgammaf_r(float x, int *signp);

long double lgammal_r(long double x, int *signp);

double remquo(double x, double y, int *quo);

float remquof(float x, float y, int *quo);

long double remquol(long double x, long double y, int *quo);
