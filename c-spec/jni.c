#include "specfunc.h"

typedef unsigned char   jboolean;
typedef unsigned short  jchar;
typedef short           jshort;
typedef float           jfloat;
typedef double          jdouble;
typedef int          	jint;

typedef jint            jsize;

struct _jobject;

typedef struct _jobject *jobject;
typedef jobject jclass;
typedef jobject jthrowable;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jbooleanArray;
typedef jarray jbyteArray;
typedef jarray jcharArray;
typedef jarray jshortArray;
typedef jarray jintArray;
typedef jarray jlongArray;
typedef jarray jfloatArray;
typedef jarray jdoubleArray;
typedef jarray jobjectArray;

struct JNIEnv_;
typedef struct JNIEnv_ JNIEnv;

#define RES_MAY_BE_NULL jobject *res;\
    					sf_overwrite(&res);\
    					sf_set_possible_null(res);\
    					return res;

const char * GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy) {
	RES_MAY_BE_NULL
}

jobjectArray  NewObjectArray(JNIEnv *env, jsize length, jclass elementClass, jobject initialElement) {
	RES_MAY_BE_NULL
}

jbooleanArray NewBooleanArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}

jbyteArray    NewByteArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}

jcharArray    NewCharArray(JNIEnv *env, jsize length) {
}

jshortArray   NewShortArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}

jintArray     NewIntArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}

jlongArray    NewLongArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}

jfloatArray   NewFloatArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}

jdoubleArray  NewDoubleArray(JNIEnv *env, jsize length) {
	RES_MAY_BE_NULL
}
