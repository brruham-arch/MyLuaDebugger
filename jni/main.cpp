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
typedef void (*lua_Hook)(lua_State*, lua_Debug*);
typedef lua_State* (*luaL_newstate_t)(void);
typedef void       (*lua_sethook_t)(lua_State*, lua_Hook, int, int);
typedef int        (*lua_getinfo_t)(lua_State*, const char*, lua_Debug*);
typedef int        (*lua_getstack_t)(lua_State*, int, lua_Debug*);

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
static lua_getstack_t  g_getstack      = NULL;

// ── Data struktur: funcName -> [script1, script2, ...] ───────
#define MAX_FUNCS    1500   // max fungsi unik
#define MAX_SCRIPTS  40     // max script per fungsi
#define FUNC_LEN     64
#define SCRIPT_LEN   48

struct FuncEntry {
    char  name[FUNC_LEN];
    char  scripts[MAX_SCRIPTS][SCRIPT_LEN];
    int   script_count;
    bool  used;
};

static FuncEntry      g_entries[MAX_FUNCS];
static int            g_entry_count = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool           g_dirty = false; // ada data baru sejak flush terakhir

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// Cari atau buat entry untuk fungsi ini
static FuncEntry* getEntry(const char* funcName) {
    for (int i = 0; i < g_entry_count; i++) {
        if (strcmp(g_entries[i].name, funcName) == 0)
            return &g_entries[i];
    }
    if (g_entry_count >= MAX_FUNCS) return NULL;
    FuncEntry* e = &g_entries[g_entry_count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->name, funcName, FUNC_LEN-1);
    e->used = true;
    return e;
}

// Tambah script ke entry — skip kalau sudah ada (deduplicate)
static void addScript(FuncEntry* e, const char* scriptName) {
    for (int i = 0; i < e->script_count; i++) {
        if (strcmp(e->scripts[i], scriptName) == 0)
            return; // sudah ada
    }
    if (e->script_count >= MAX_SCRIPTS) return;
    strncpy(e->scripts[e->script_count++], scriptName, SCRIPT_LEN-1);
    g_dirty = true;
}

// Ambil basename dari path script
static void getBasename(const char* src, char* out, size_t sz) {
    if (!src || src[0] == '=') { strncpy(out, "?", sz); return; }
    const char* s = src[0] == '@' ? src+1 : src;
    const char* base = strrchr(s, '/');
    base = base ? base+1 : s;
    strncpy(out, base, sz-1);
    out[sz-1] = '\0';
}

// Cek apakah source adalah user script (bukan lib internal)
static bool isUserScript(const char* src) {
    if (!src || src[0] == '=') return false;
    if (!strstr(src, ".lua")) return false;
    return true;
}

// Flush ke file dalam format ringkas
static void flushToFile() {
    if (!g_dirty) return;

    FILE* f = fopen("/sdcard/luadbg_api_usage.log", "w");
    if (!f) return;

    fprintf(f, "=== API Usage (fungsi: script yang menggunakan) ===\n");
    fprintf(f, "Total fungsi terpantau: %d\n\n", g_entry_count);

    for (int i = 0; i < g_entry_count; i++) {
        FuncEntry* e = &g_entries[i];
        if (e->script_count == 0) continue;

        // Format: funcName : script1, script2, script3
        fprintf(f, "%-40s: ", e->name);
        for (int j = 0; j < e->script_count; j++) {
            if (j > 0) fprintf(f, ", ");
            fprintf(f, "%s", e->scripts[j]);
        }
        fprintf(f, "\n");
    }
    fclose(f);
    g_dirty = false;
}

// ── Lua hook ─────────────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void LuaDebugger_hook(lua_State* L, lua_Debug* ar) {
    if (!g_getinfo) return;
    g_getinfo(L, "nS", ar); // hanya butuh name dan source

    // Skip kalau tidak ada nama fungsi
    if (!ar->name) return;

    // Kita track semua fungsi, tapi caller harus dari user script
    // Cari dari mana fungsi ini dipanggil
    char caller_script[SCRIPT_LEN] = {0};

    if (ar->source && isUserScript(ar->source)) {
        // Fungsi Lua — source langsung adalah scriptnya
        getBasename(ar->source, caller_script, sizeof(caller_script));
    } else if (g_getstack) {
        // Fungsi C dipanggil dari Lua — cari caller di stack level 1
        lua_Debug caller;
        memset(&caller, 0, sizeof(caller));
        if (g_getstack(L, 1, &caller) && g_getinfo(L, "S", &caller)) {
            if (caller.source && isUserScript(caller.source)) {
                getBasename(caller.source, caller_script, sizeof(caller_script));
            }
        }
    }

    // Skip kalau caller bukan user script
    if (caller_script[0] == '\0') return;

    pthread_mutex_lock(&g_mutex);
    FuncEntry* e = getEntry(ar->name);
    if (e) addScript(e, caller_script);
    pthread_mutex_unlock(&g_mutex);
}

// ── GOT hook ─────────────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
lua_State* LuaDebugger_newstate_hook(void) {
    lua_State* L = g_orig_newstate();
    if (L && g_sethook) {
        void* hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_hook");
        if (hookFn)
            g_sethook(L, (lua_Hook)hookFn, LUA_MASKCALL, 0);
    }
    return L;
}

// ── Flush thread ─────────────────────────────────────────────
static void* flushThread(void*) {
    while (true) {
        sleep(5);
        pthread_mutex_lock(&g_mutex);
        flushToFile();
        pthread_mutex_unlock(&g_mutex);
    }
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

static bool patchGOT(uintptr_t base, const char* symName, void* newFunc) {
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
        if (d->d_tag == DT_SYMTAB)   symtab    = (Elf32_Sym*) (base + d->d_un.d_ptr);
        if (d->d_tag == DT_STRTAB)   strtab    = (const char*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_JMPREL)   jmprel    = (Elf32_Rel*) (base + d->d_un.d_ptr);
        if (d->d_tag == DT_PLTRELSZ) jmprel_sz = d->d_un.d_val;
    }
    if (!symtab || !strtab || !jmprel) return false;
    for (size_t i = 0; i < jmprel_sz / sizeof(Elf32_Rel); i++) {
        uint32_t sym_idx = ELF32_R_SYM(jmprel[i].r_info);
        if (strcmp(strtab + symtab[sym_idx].st_name, symName) != 0) continue;
        uint32_t* got = (uint32_t*)(base + jmprel[i].r_offset);
        uintptr_t page = (uintptr_t)got & ~((uintptr_t)(getpagesize()-1));
        mprotect((void*)page, getpagesize(), PROT_READ | PROT_WRITE);
        *got = (uint32_t)(uintptr_t)newFunc;
        mprotect((void*)page, getpagesize(), PROT_READ);
        char buf[128];
        snprintf(buf, sizeof(buf), "[GOT] patched '%s' -> 0x%x", symName, (unsigned int)newFunc);
        writeLog(buf); return true;
    }
    return false;
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("=== LuaDebugger API Tracker START ===");

    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    memset(g_entries, 0, sizeof(g_entries));

    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] FAILED"); return; }

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] FAILED"); return; }

    g_orig_newstate = (luaL_newstate_t)dlsym(luajitHandle, "luaL_newstate");
    g_sethook       = (lua_sethook_t)  dlsym(luajitHandle, "lua_sethook");
    g_getinfo       = (lua_getinfo_t)  dlsym(luajitHandle, "lua_getinfo");
    g_getstack      = (lua_getstack_t) dlsym(luajitHandle, "lua_getstack");
    if (!g_orig_newstate || !g_sethook || !g_getinfo) {
        writeLog("[Step3] symbol FAILED"); return;
    }

    char selfPath[512] = {0};
    getSelfPath(selfPath, sizeof(selfPath));
    if (!selfPath[0]) strcpy(selfPath, "libLuaDebugger.so");

    void* selfHandle = dlopen(selfPath, RTLD_NOW | RTLD_GLOBAL);
    if (!selfHandle) { writeLog("[Self] FAILED"); return; }

    void* hookFn = dlsym(selfHandle, "LuaDebugger_newstate_hook");
    if (!hookFn) hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_newstate_hook");
    if (!hookFn) { writeLog("[Self] hook FAILED"); return; }

    uintptr_t hookFn_thumb = ((uintptr_t)hookFn & ~1u) | 1u;
    uintptr_t monetBase = getLibBase("libmonetloader.so");
    if (!monetBase) { writeLog("[GOT] base FAILED"); return; }

    if (patchGOT(monetBase, "luaL_newstate", (void*)hookFn_thumb)) {
        writeLog("[GOT] Patch SUCCESS");
        writeLog("[INFO] Output: /sdcard/luadbg_api_usage.log");
        writeLog("[INFO] Format: fungsi : script1, script2, ...");
        writeLog("[INFO] Deduplicated — tiap script dicatat 1x per fungsi");

        pthread_t tid;
        pthread_create(&tid, NULL, flushThread, NULL);
        pthread_detach(tid);
    }
}
