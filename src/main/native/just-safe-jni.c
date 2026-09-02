#include <jni.h>

/*
 * Verifier-owned JNI fixture.  It has no imports, file/network access, or process
 * creation; the only observable result is a fixed return value used by the child
 * probe to prove that a native call returned normally.
 */
JNIEXPORT jint JNICALL Java_fixture_NativeFixture_value(JNIEnv *env, jclass type) {
    (void) env;
    (void) type;
    return (jint) 0x4a555354;
}
