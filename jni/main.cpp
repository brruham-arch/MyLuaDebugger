#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct lua_State lua_State;
typedef void (*lua_settop_t)(lua_State*, int);
typedef int  (*DobbyHook_t)(void*, void*, void**);

static lua_State*   g_L              = NULL;
static lua_settop_t g_orig_settop    = NULL;

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// Hook lua_settop — fungsi paling simpel, hanya baca/tulis stack
static void my_settop(lua_State* L, int idx) {
    if (!g_L && L) {
        g_L = L;
        char buf[128];
        snprintf(buf, sizeof(buf), "[Step4] lua_State* CAPTURED via settop = 0x%x", (unsigned int)L);
        writeLog(buf);
        LOGI("%s", buf);
    }
    g_orig_settop(L, idx);
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    // Cegah double-init
    static int initialized = 0;
    if (initialized) { writeLog("[WARN] double load, skip"); return; }
    initialized = 1;

    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] FAILED"); return; }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] dlopen libluajit FAILED"); return; }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    void* settop_addr = dlsym(luajitHandle, "lua_settop");
    if (!settop_addr) { writeLog("[Step3] lua_settop symbol FAILED"); return; }

    char buf[128];
    snprintf(buf, sizeof(buf), "[Step3] lua_settop addr=0x%x", (unsigned int)settop_addr);
    writeLog(buf);

    void* dobbyHandle = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobbyHandle) { writeLog("[Step4] dlopen libdobby FAILED"); return; }
    writeLog("[Step4] dlopen libdobby.so SUCCESS");

    DobbyHook_t DobbyHook = (DobbyHook_t)dlsym(dobbyHandle, "DobbyHook");
    if (!DobbyHook) { writeLog("[Step4] DobbyHook symbol FAILED"); return; }

    int ret = DobbyHook(settop_addr, (void*)my_settop, (void**)&g_orig_settop);
    snprintf(buf, sizeof(buf), "[Step4] DobbyHook lua_settop result=%d", ret);
    writeLog(buf);

    if (ret == 0) {
        writeLog("[Step4] Hook OK — menunggu lua_State* dari settop pertama...");
    }
}
