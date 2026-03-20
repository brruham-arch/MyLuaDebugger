#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    // Step 2: coba dapat handle libmonetloader.so
    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOLOAD | RTLD_GLOBAL);
    if (monetHandle) {
        writeLog("[Step2] dlopen libmonetloader.so SUCCESS");
        LOGI("dlopen libmonetloader.so SUCCESS");
    } else {
        const char* err = dlerror();
        char buf[256];
        snprintf(buf, sizeof(buf), "[Step2] dlopen FAILED: %s", err ? err : "unknown");
        writeLog(buf);
        LOGI("dlopen FAILED: %s", err ? err : "unknown");
    }
}
