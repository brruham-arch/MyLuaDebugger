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

    // Step 2: coba beberapa nama kandidat libmonetloader
    const char* candidates[] = {
        "libmonetloader.so",
        "libMoNetLoader.so",
        "libmonet.so",
        "libmoonloader.so",
        NULL
    };

    void* monetHandle = NULL;
    const char* loadedName = NULL;

    for (int i = 0; candidates[i] != NULL; i++) {
        // coba RTLD_NOLOAD dulu (kalau sudah di-load sebelumnya)
        monetHandle = dlopen(candidates[i], RTLD_NOLOAD | RTLD_GLOBAL);
        if (!monetHandle) {
            // kalau belum ada, load sendiri
            monetHandle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        }
        if (monetHandle) {
            loadedName = candidates[i];
            break;
        }
    }

    if (monetHandle && loadedName) {
        char buf[256];
        snprintf(buf, sizeof(buf), "[Step2] dlopen SUCCESS: %s", loadedName);
        writeLog(buf);
        LOGI("dlopen SUCCESS: %s", loadedName);

        // Step 3: cari lua_State* via dlsym
        const char* symCandidates[] = {
            "g_LuaState",
            "gLuaState",
            "luaState",
            "L",
            "gL",
            "lua_state",
            "monetLuaState",
            NULL
        };

        void* symAddr = NULL;
        const char* foundSym = NULL;

        for (int i = 0; symCandidates[i] != NULL; i++) {
            symAddr = dlsym(monetHandle, symCandidates[i]);
            if (symAddr) {
                foundSym = symCandidates[i];
                break;
            }
        }

        if (symAddr && foundSym) {
            char buf2[256];
            snprintf(buf2, sizeof(buf2), "[Step3] lua_State* found via symbol: '%s' addr=0x%x", foundSym, (unsigned int)symAddr);
            writeLog(buf2);
            LOGI("%s", buf2);
        } else {
            writeLog("[Step3] dlsym FAILED: tidak ada symbol yang cocok, perlu offset manual");
            LOGI("dlsym FAILED: tidak ada symbol yang cocok");
        }

    } else {
        const char* err = dlerror();
        char buf[256];
        snprintf(buf, sizeof(buf), "[Step2] dlopen FAILED semua kandidat: %s", err ? err : "unknown");
        writeLog(buf);
        LOGI("dlopen FAILED: %s", err ? err : "unknown");
    }
}
