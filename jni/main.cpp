#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#define TAG "LuaDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct lua_State lua_State;
typedef struct lua_Debug lua_Debug;
typedef void   (*lua_Hook)(lua_State*, lua_Debug*);
typedef lua_State* (*luaL_newstate_t)(void);
typedef void       (*lua_sethook_t)(lua_State*, lua_Hook, int, int);
typedef int        (*lua_getinfo_t)(lua_State*, const char*, lua_Debug*);

#define LUA_MASKCALL 1

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

static luaL_newstate_t g_orig_newstate = NULL;
static lua_sethook_t   g_sethook       = NULL;
static lua_getinfo_t   g_getinfo       = NULL;
static char            g_target[128]   = {0};

// ── Buffer ────────────────────────────────────────────────────
#define MAX_FUNCS   512
#define FUNC_LEN    64

static char   g_funcs[MAX_FUNCS][FUNC_LEN];
static int    g_func_count = 0;
static bool   g_dirty      = false;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// Deduplicated insert
static void addFunc(const char* name) {
    for (int i = 0; i < g_func_count; i++)
        if (strcmp(g_funcs[i], name) == 0) return;
    if (g_func_count >= MAX_FUNCS) return;
    strncpy(g_funcs[g_func_count++], name, FUNC_LEN-1);
    g_dirty = true;
}

static void flush() {
    if (!g_dirty) return;
    FILE* f = fopen("/sdcard/luadbg_funcs.txt", "w");
    if (!f) return;
    fprintf(f, "=== Fungsi yang dipanggil oleh: %s ===\n", g_target);
    fprintf(f, "Total: %d fungsi\n\n", g_func_count);
    for (int i = 0; i < g_func_count; i++)
        fprintf(f, "%s\n", g_funcs[i]);
    fclose(f);
    g_dirty = false;
}

// ── Hook ──────────────────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void LuaDebugger_hook(lua_State* L, lua_Debug* ar) {
    if (!g_getinfo || !g_target[0]) return;
    g_getinfo(L, "nS", ar);

    // Hanya dari target script
    if (!ar->source) return;
    const char* src = ar->source[0] == '@' ? ar->source+1 : ar->source;
    const char* base = strrchr(src, '/');
    base = base ? base+1 : src;
    if (!strstr(base, g_target)) return;

    if (!ar->name) return;

    pthread_mutex_lock(&g_mutex);
    addFunc(ar->name);
    pthread_mutex_unlock(&g_mutex);
}

extern "C" __attribute__((visibility("default")))
lua_State* LuaDebugger_newstate_hook(void) {
    lua_State* L = g_orig_newstate();
    if (L && g_sethook) {
        void* fn = dlsym(RTLD_DEFAULT, "LuaDebugger_hook");
        if (fn) g_sethook(L, (lua_Hook)fn, LUA_MASKCALL, 0);
    }
    return L;
}

static void* flushThread(void*) {
    while (true) { sleep(3); pthread_mutex_lock(&g_mutex); flush(); pthread_mutex_unlock(&g_mutex); }
    return NULL;
}

// ── Helpers ──────────────────────────────────────────────────
static uintptr_t getLibBase(const char* name) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512]; uintptr_t base = UINTPTR_MAX;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        uintptr_t s = (uintptr_t)strtoul(line, NULL, 16);
        if (s < base) base = s;
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
        fclose(f); return true;
    }
    fclose(f); return false;
}

static bool patchGOT(uintptr_t base, const char* sym, void* fn) {
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)base;
    if (ehdr->e_ident[0] != 0x7f) return false;
    Elf32_Phdr* phdr = (Elf32_Phdr*)(base + ehdr->e_phoff);
    Elf32_Dyn* dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++)
        if (phdr[i].p_type == PT_DYNAMIC) { dyn = (Elf32_Dyn*)(base + phdr[i].p_vaddr); break; }
    if (!dyn) return false;
    Elf32_Sym* symtab = NULL; const char* strtab = NULL;
    Elf32_Rel* jmprel = NULL; size_t jmprel_sz = 0;
    for (Elf32_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB)   symtab    = (Elf32_Sym*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_STRTAB)   strtab    = (const char*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_JMPREL)   jmprel    = (Elf32_Rel*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_PLTRELSZ) jmprel_sz = d->d_un.d_val;
    }
    if (!symtab || !strtab || !jmprel) return false;
    for (size_t i = 0; i < jmprel_sz / sizeof(Elf32_Rel); i++) {
        uint32_t idx = ELF32_R_SYM(jmprel[i].r_info);
        if (strcmp(strtab + symtab[idx].st_name, sym) != 0) continue;
        uint32_t* got = (uint32_t*)(base + jmprel[i].r_offset);
        uintptr_t page = (uintptr_t)got & ~((uintptr_t)(getpagesize()-1));
        mprotect((void*)page, getpagesize(), PROT_READ | PROT_WRITE);
        *got = (uint32_t)(uintptr_t)fn;
        mprotect((void*)page, getpagesize(), PROT_READ);
        return true;
    }
    return false;
}

__attribute__((constructor))
static void onLoad() {
    writeLog("=== LuaDebugger START ===");
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    // Baca config
    FILE* cfg = fopen("/sdcard/luadbg_config.txt", "r");
    if (cfg) {
        char line[256];
        while (fgets(line, sizeof(line), cfg)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strncmp(line, "target=", 7) == 0)
                strncpy(g_target, line+7, sizeof(g_target)-1);
        }
        fclose(cfg);
    }

    if (!g_target[0]) {
        writeLog("[CONFIG] target kosong! Buat /sdcard/luadbg_config.txt");
        writeLog("[CONFIG] Isi: target=namaScript.lua");
        return;
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "[CONFIG] target=%s", g_target);
    writeLog(buf);

    void* luajit = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajit) { writeLog("[LuaJIT] FAILED"); return; }

    g_orig_newstate = (luaL_newstate_t)dlsym(luajit, "luaL_newstate");
    g_sethook       = (lua_sethook_t)  dlsym(luajit, "lua_sethook");
    g_getinfo       = (lua_getinfo_t)  dlsym(luajit, "lua_getinfo");
    if (!g_orig_newstate || !g_sethook || !g_getinfo) {
        writeLog("[LuaJIT] symbol FAILED"); return;
    }

    dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);

    char selfPath[512] = {0};
    getSelfPath(selfPath, sizeof(selfPath));
    if (!selfPath[0]) strcpy(selfPath, "libLuaDebugger.so");

    void* self = dlopen(selfPath, RTLD_NOW | RTLD_GLOBAL);
    if (!self) { writeLog("[Self] FAILED"); return; }

    void* hookFn = dlsym(self, "LuaDebugger_newstate_hook");
    if (!hookFn) hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_newstate_hook");
    if (!hookFn) { writeLog("[Self] hook FAILED"); return; }

    uintptr_t thumb = ((uintptr_t)hookFn & ~1u) | 1u;
    uintptr_t base  = getLibBase("libmonetloader.so");
    if (!base) { writeLog("[GOT] base FAILED"); return; }

    if (patchGOT(base, "luaL_newstate", (void*)thumb)) {
        writeLog("[GOT] Patch SUCCESS");
        writeLog("[INFO] Output: /sdcard/luadbg_funcs.txt");

        pthread_t tid;
        pthread_create(&tid, NULL, flushThread, NULL);
        pthread_detach(tid);
    }
}
