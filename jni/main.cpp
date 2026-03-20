#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ── typedefs Lua ──────────────────────────────────────────────
typedef struct lua_State lua_State;
typedef struct lua_Debug lua_Debug;
typedef void (*lua_Hook)(lua_State*, lua_Debug*);
typedef int  (*lua_pcall_t)(lua_State*, int, int, int);
typedef void (*lua_sethook_t)(lua_State*, lua_Hook, int, int);
typedef int  (*lua_getinfo_t)(lua_State*, const char*, lua_Debug*);

#define LUA_MASKCALL  1
#define LUA_MASKRET   2
#define LUA_MASKLINE  4

struct lua_Debug {
    int event;
    const char* name;
    const char* namewhat;
    const char* what;
    const char* source;
    int currentline;
    int nups;
    int linedefined;
    int lastlinedefined;
    char short_src[60];
    int i_ci;
};

// ── Dobby API ─────────────────────────────────────────────────
typedef int (*DobbyHook_t)(void* addr, void* replace, void** origin);

// ── Globals ───────────────────────────────────────────────────
static lua_State*    g_L         = NULL;
static lua_sethook_t g_sethook   = NULL;
static lua_getinfo_t g_getinfo   = NULL;
static lua_pcall_t   g_orig_pcall = NULL;

// ── Log helper ────────────────────────────────────────────────
static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// ── Lua debug hook ────────────────────────────────────────────
static void luaHook(lua_State* L, lua_Debug* ar) {
    if (!g_getinfo) return;
    g_getinfo(L, "nSl", ar);

    char buf[256];
    const char* evName = (ar->event == 0) ? "CALL" :
                         (ar->event == 1) ? "RET"  : "LINE";
    snprintf(buf, sizeof(buf), "[Hook] %s | src=%.60s line=%d func=%.60s",
        evName,
        ar->source      ? ar->source   : "?",
        ar->currentline,
        ar->name        ? ar->name     : "(anon)"
    );
    writeLog(buf);
}

// ── Hook: lua_pcall ───────────────────────────────────────────
static int my_pcall(lua_State* L, int nargs, int nresults, int errfunc) {
    // Capture lua_State* pertama kali
    if (!g_L && L) {
        g_L = L;
        writeLog("[Step4] lua_State* captured via lua_pcall hook!");

        // Langsung pasang debug hook
        if (g_sethook) {
            g_sethook(g_L, luaHook, LUA_MASKCALL | LUA_MASKRET, 0);
            writeLog("[Step4] lua_sethook terpasang -> monitoring CALL & RET");
        }
    }
    // Tetap jalankan pcall asli
    return g_orig_pcall(L, nargs, nresults, errfunc);
}

// ── Main init ─────────────────────────────────────────────────
__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    // Step 2
    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] FAILED"); return; }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    // Step 3
    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] dlopen libluajit FAILED"); return; }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    g_sethook = (lua_sethook_t)dlsym(luajitHandle, "lua_sethook");
    g_getinfo = (lua_getinfo_t)dlsym(luajitHandle, "lua_getinfo");
    void* pcall_addr = dlsym(luajitHandle, "lua_pcall");

    char buf[256];
    snprintf(buf, sizeof(buf), "[Step3] sethook=0x%x getinfo=0x%x pcall=0x%x",
        (unsigned int)g_sethook,
        (unsigned int)g_getinfo,
        (unsigned int)pcall_addr);
    writeLog(buf);

    if (!g_sethook || !g_getinfo || !pcall_addr) {
        writeLog("[Step3] Ada fn pointer NULL, abort"); return;
    }
    writeLog("[Step3] Semua function pointer OK");

    // Step 4: Dobby hook lua_pcall
    void* dobbyHandle = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!dobbyHandle) { writeLog("[Step4] dlopen libdobby FAILED"); return; }
    writeLog("[Step4] dlopen libdobby.so SUCCESS");

    DobbyHook_t DobbyHook = (DobbyHook_t)dlsym(dobbyHandle, "DobbyHook");
    if (!DobbyHook) { writeLog("[Step4] DobbyHook symbol FAILED"); return; }
    writeLog("[Step4] DobbyHook symbol OK");

    int ret = DobbyHook(pcall_addr, (void*)my_pcall, (void**)&g_orig_pcall);
    snprintf(buf, sizeof(buf), "[Step4] DobbyHook lua_pcall result=%d", ret);
    writeLog(buf);

    if (ret == 0) {
        writeLog("[Step4] Hook terpasang! Menunggu lua_pcall pertama...");
    } else {
        writeLog("[Step4] DobbyHook FAILED, cek result code");
    }
}
