#include <jni.h>
#include <string>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <jni.h>
extern "C"
JNIEXPORT jstring





JNICALL
Java_com_makelove_so_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}




jstring getString(JNIEnv *env, jobject){
    std::string hello = "Hello from so";
    return env->NewStringUTF(hello.c_str());
}



JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void *reserved) {
    JNIEnv* env = NULL;
    jint resultstr = -1;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass jclazz = env->FindClass("com/makelove/so/MainActivity");

    JNINativeMethod natives[] = {
            {"getSectionString", "()Ljava/lang/String;", (void*)getString}

    };
    env->RegisterNatives(jclazz, natives,1);


    env->DeleteLocalRef(jclazz);

    return JNI_VERSION_1_6;
}
