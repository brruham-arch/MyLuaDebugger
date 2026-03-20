#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct lua_State lua_State;
typedef int (*lua_pcall_t)(lua_State*, int, int, int);
typedef int (*DobbyHook_t)(void*, void*, void**);

static lua_State*   g_L           = NULL;
static lua_pcall_t  g_orig_pcall  = NULL;

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// ── Hook: lua_pcall — hanya capture lua_State*, langsung return ──
static int my_pcall(lua_State* L, int nargs, int nresults, int errfunc) {
    if (!g_L && L) {
        g_L = L;
        char buf[128];
        snprintf(buf, sizeof(buf), "[Step4] lua_State* CAPTURED = 0x%x", (unsigned int)L);
        writeLog(buf);
        LOGI("%s", buf);
    }
    return g_orig_pcall(L, nargs, nresults, errfunc);
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] FAILED"); return; }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] dlopen libluajit FAILED"); return; }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    void* pcall_addr = dlsym(luajitHandle, "lua_pcall");
    if (!pcall_addr) { writeLog("[Step3] lua_pcall symbol FAILED"); return; }

    char buf[128];
    snprintf(buf, sizeof(buf), "[Step3] lua_pcall addr=0x%x", (unsigned int)pcall_addr);
    writeLog(buf);

    void* dobbyHandle = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobbyHandle) { writeLog("[Step4] dlopen libdobby FAILED"); return; }
    writeLog("[Step4] dlopen libdobby.so SUCCESS");

    DobbyHook_t DobbyHook = (DobbyHook_t)dlsym(dobbyHandle, "DobbyHook");
    if (!DobbyHook) { writeLog("[Step4] DobbyHook symbol FAILED"); return; }

    int ret = DobbyHook(pcall_addr, (void*)my_pcall, (void**)&g_orig_pcall);
    snprintf(buf, sizeof(buf), "[Step4] DobbyHook result=%d", ret);
    writeLog(buf);

    if (ret == 0) {
        writeLog("[Step4] Hook OK — menunggu lua_State* dari pcall pertama...");
    }
}
