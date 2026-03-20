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

    // Step 2: dlopen libmonetloader.so
    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) {
        writeLog("[Step2] dlopen libmonetloader.so FAILED");
        return;
    }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    // Step 3: dlopen libluajit, dapat function pointers penting
    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) {
        writeLog("[Step3] dlopen libluajit-5.1.so FAILED");
        return;
    }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    void* fn_sethook = dlsym(luajitHandle, "lua_sethook");
    void* fn_getinfo = dlsym(luajitHandle, "lua_getinfo");
    void* fn_pcall   = dlsym(luajitHandle, "lua_pcall");

    char buf[512];
    snprintf(buf, sizeof(buf),
        "[Step3] lua_sethook=0x%x lua_getinfo=0x%x lua_pcall=0x%x",
        (unsigned int)fn_sethook,
        (unsigned int)fn_getinfo,
        (unsigned int)fn_pcall
    );
    writeLog(buf);
    LOGI("%s", buf);

    if (fn_sethook && fn_getinfo && fn_pcall) {
        writeLog("[Step3] Semua function pointer OK -> siap Step 4 (hook lua_pcall untuk capture lua_State*)");
    } else {
        writeLog("[Step3] Ada function pointer NULL, cek hasil di atas");
    }
}
