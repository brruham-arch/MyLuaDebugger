#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct lua_State lua_State;
typedef lua_State* (*luaL_newstate_t)(void);
typedef int        (*DobbyHook_t)(void*, void*, void**);

static lua_State*      g_L             = NULL;
static luaL_newstate_t g_orig_newstate = NULL;

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

static lua_State* my_newstate(void) {
    lua_State* L = g_orig_newstate();
    if (!g_L && L) {
        g_L = L;
        char buf[128];
        snprintf(buf, sizeof(buf), "[Step4] lua_State* CAPTURED = 0x%x", (unsigned int)L);
        writeLog(buf);
        LOGI("%s", buf);
    }
    return L;
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    static int initialized = 0;
    if (initialized) { writeLog("[WARN] double load, skip"); return; }
    initialized = 1;

    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] FAILED"); return; }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] dlopen libluajit FAILED"); return; }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    void* newstate_addr = dlsym(luajitHandle, "luaL_newstate");
    if (!newstate_addr) { writeLog("[Step3] luaL_newstate symbol FAILED"); return; }

    // Cek apakah Thumb: bit 0 dari symbol value di ELF
    // dlsym return tanpa Thumb bit — kita tambah |1 untuk Thumb
    uintptr_t addr_raw  = (uintptr_t)newstate_addr;
    uintptr_t addr_thumb = addr_raw | 1;  // paksa Thumb

    char buf[256];
    snprintf(buf, sizeof(buf), "[Step3] luaL_newstate raw=0x%x thumb=0x%x",
        (unsigned int)addr_raw, (unsigned int)addr_thumb);
    writeLog(buf);

    void* dobbyHandle = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobbyHandle) { writeLog("[Step4] dlopen libdobby FAILED"); return; }
    writeLog("[Step4] dlopen libdobby.so SUCCESS");

    DobbyHook_t DobbyHook = (DobbyHook_t)dlsym(dobbyHandle, "DobbyHook");
    if (!DobbyHook) { writeLog("[Step4] DobbyHook symbol FAILED"); return; }

    // Pasang hook dengan Thumb address (|1)
    int ret = DobbyHook((void*)addr_thumb, (void*)my_newstate, (void**)&g_orig_newstate);
    snprintf(buf, sizeof(buf), "[Step4] DobbyHook luaL_newstate (Thumb) result=%d", ret);
    writeLog(buf);

    if (ret == 0) {
        writeLog("[Step4] Hook OK — menunggu luaL_newstate...");
    }
}
