#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ── Lua types ────────────────────────────────────────────────
typedef struct lua_State lua_State;
typedef struct lua_Debug lua_Debug;
typedef void (*lua_Hook)(lua_State*, lua_Debug*);
typedef lua_State* (*luaL_newstate_t)(void);
typedef void       (*lua_sethook_t)(lua_State*, lua_Hook, int, int);
typedef int        (*lua_getinfo_t)(lua_State*, const char*, lua_Debug*);

#define LUA_MASKCALL  1
#define LUA_MASKRET   2

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

// ── Globals ──────────────────────────────────────────────────
static lua_State*      g_L             = NULL;
static luaL_newstate_t g_orig_newstate = NULL;
static lua_sethook_t   g_sethook       = NULL;
static lua_getinfo_t   g_getinfo       = NULL;

// ── Log helper ───────────────────────────────────────────────
static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// ── Lua debug hook ───────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void LuaDebugger_hook(lua_State* L, lua_Debug* ar) {
    if (!g_getinfo) return;
    g_getinfo(L, "nSl", ar);

    const char* ev = (ar->event == 0) ? "CALL" : "RET";
    char buf[256];
    snprintf(buf, sizeof(buf), "[%s] %s | %s:%d",
        ev,
        ar->name   ? ar->name   : "(anon)",
        ar->source ? ar->source : "?",
        ar->currentline
    );
    writeLog(buf);
}

// ── GOT hook: luaL_newstate ───────────────────────────────────
extern "C" __attribute__((visibility("default")))
lua_State* LuaDebugger_newstate_hook(void) {
    lua_State* L = g_orig_newstate();
    if (!g_L && L) {
        g_L = L;
        char buf[128];
        snprintf(buf, sizeof(buf), "[HOOK] lua_State* CAPTURED = 0x%x", (unsigned int)L);
        writeLog(buf);
        LOGI("%s", buf);

        // Pasang debug hook sekarang
        if (g_sethook) {
            // Ambil fn hook via RTLD_DEFAULT agar dari trusted region
            void* hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_hook");
            if (hookFn) {
                g_sethook(L, (lua_Hook)hookFn, LUA_MASKCALL | LUA_MASKRET, 0);
                writeLog("[HOOK] lua_sethook terpasang -> monitoring CALL & RET");
            } else {
                writeLog("[HOOK] LuaDebugger_hook symbol not found");
            }
        }
    }
    return L;
}

// ── Helpers ──────────────────────────────────────────────────
static uintptr_t getLibBase(const char* name) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = UINTPTR_MAX;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        uintptr_t start = (uintptr_t)strtoul(line, NULL, 16);
        if (start < base) base = start;
    }
    fclose(f);
    return (base == UINTPTR_MAX) ? 0 : base;
}

static bool getSelfPath(char* out, size_t sz) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libLuaDebugger.so")) continue;
        char* path = strstr(line, "/data");
        if (!path) continue;
        size_t len = strlen(path);
        if (path[len-1] == '\n') path[len-1] = '\0';
        strncpy(out, path, sz-1);
        fclose(f);
        return true;
    }
    fclose(f);
    return false;
}

static bool patchGOT(uintptr_t base, const char* symName, void* newFunc) {
    char buf[256];
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)base;
    if (ehdr->e_ident[0] != 0x7f) { writeLog("[GOT] bad ELF"); return false; }

    Elf32_Phdr* phdr = (Elf32_Phdr*)(base + ehdr->e_phoff);
    Elf32_Dyn* dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf32_Dyn*)(base + phdr[i].p_vaddr); break;
        }
    }
    if (!dyn) { writeLog("[GOT] no PT_DYNAMIC"); return false; }

    Elf32_Sym* symtab = NULL; const char* strtab = NULL;
    Elf32_Rel* jmprel = NULL; size_t jmprel_sz = 0;
    for (Elf32_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB)   symtab    = (Elf32_Sym*) (base + d->d_un.d_ptr);
        if (d->d_tag == DT_STRTAB)   strtab    = (const char*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_JMPREL)   jmprel    = (Elf32_Rel*) (base + d->d_un.d_ptr);
        if (d->d_tag == DT_PLTRELSZ) jmprel_sz = d->d_un.d_val;
    }
    if (!symtab || !strtab || !jmprel) { writeLog("[GOT] null sections"); return false; }

    for (size_t i = 0; i < jmprel_sz / sizeof(Elf32_Rel); i++) {
        uint32_t sym_idx = ELF32_R_SYM(jmprel[i].r_info);
        if (strcmp(strtab + symtab[sym_idx].st_name, symName) != 0) continue;

        uint32_t* got = (uint32_t*)(base + jmprel[i].r_offset);
        snprintf(buf, sizeof(buf), "[GOT] found '%s' GOT=0x%x cur=0x%x",
            symName, (unsigned int)got, *got);
        writeLog(buf);

        uintptr_t page = (uintptr_t)got & ~((uintptr_t)(getpagesize()-1));
        mprotect((void*)page, getpagesize(), PROT_READ | PROT_WRITE);
        *got = (uint32_t)(uintptr_t)newFunc;
        mprotect((void*)page, getpagesize(), PROT_READ);

        snprintf(buf, sizeof(buf), "[GOT] patched -> 0x%x", (unsigned int)newFunc);
        writeLog(buf);
        return true;
    }
    writeLog("[GOT] symbol not found"); return false;
}

// ── Constructor ──────────────────────────────────────────────
__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    static int initialized = 0;
    if (initialized) { writeLog("[WARN] double load, skip"); return; }
    initialized = 1;

    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] monet FAILED"); return; }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] luajit FAILED"); return; }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    g_orig_newstate = (luaL_newstate_t)dlsym(luajitHandle, "luaL_newstate");
    g_sethook       = (lua_sethook_t)  dlsym(luajitHandle, "lua_sethook");
    g_getinfo       = (lua_getinfo_t)  dlsym(luajitHandle, "lua_getinfo");

    if (!g_orig_newstate || !g_sethook || !g_getinfo) {
        writeLog("[Step3] symbol FAILED"); return;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "[Step3] newstate=0x%x sethook=0x%x getinfo=0x%x",
        (unsigned int)g_orig_newstate,
        (unsigned int)g_sethook,
        (unsigned int)g_getinfo);
    writeLog(buf);

    // dlopen self via system linker
    char selfPath[512] = {0};
    getSelfPath(selfPath, sizeof(selfPath));
    if (!selfPath[0]) strcpy(selfPath, "libLuaDebugger.so");

    void* selfHandle = dlopen(selfPath, RTLD_NOW | RTLD_GLOBAL);
    if (!selfHandle) { writeLog("[Self] dlopen FAILED"); return; }
    writeLog("[Self] dlopen self SUCCESS");

    void* hookFn = dlsym(selfHandle, "LuaDebugger_newstate_hook");
    if (!hookFn) hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_newstate_hook");
    if (!hookFn) { writeLog("[Self] newstate_hook symbol FAILED"); return; }

    uintptr_t hookFn_thumb = ((uintptr_t)hookFn & ~1u) | 1u;
    snprintf(buf, sizeof(buf), "[Self] hook=0x%x", (unsigned int)hookFn_thumb);
    writeLog(buf);

    uintptr_t monetBase = getLibBase("libmonetloader.so");
    if (!monetBase) { writeLog("[GOT] base FAILED"); return; }

    if (patchGOT(monetBase, "luaL_newstate", (void*)hookFn_thumb)) {
        writeLog("[GOT] Patch SUCCESS — menunggu luaL_newstate...");
    }
}
