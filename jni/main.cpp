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
static luaL_newstate_t g_orig_newstate = NULL;
static lua_sethook_t   g_sethook       = NULL;
static lua_getinfo_t   g_getinfo       = NULL;
static lua_getstack_t  g_getstack      = NULL;

// ── Buffer per script ─────────────────────────────────────────
#define MAX_SCRIPTS   32
#define BUF_LINES     200
#define LINE_LEN      256

struct ScriptBuf {
    char  name[128];       // nama file log
    char  lines[BUF_LINES][LINE_LEN];
    int   count;
    bool  used;
};

static ScriptBuf  g_bufs[MAX_SCRIPTS];
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static ScriptBuf* getOrCreateBuf(const char* scriptPath) {
    // Buat nama file dari path
    const char* base = strrchr(scriptPath, '/');
    base = base ? base + 1 : scriptPath;
    if (base[0] == '@') base++;

    char fname[128];
    snprintf(fname, sizeof(fname), "luadbg_%s.log", base);
    for (char* p = fname; *p; p++)
        if (*p == '/' || *p == ':' || *p == ' ') *p = '_';

    // Cari yang sudah ada
    for (int i = 0; i < MAX_SCRIPTS; i++) {
        if (g_bufs[i].used && strcmp(g_bufs[i].name, fname) == 0)
            return &g_bufs[i];
    }
    // Buat slot baru
    for (int i = 0; i < MAX_SCRIPTS; i++) {
        if (!g_bufs[i].used) {
            g_bufs[i].used  = true;
            g_bufs[i].count = 0;
            strncpy(g_bufs[i].name, fname, sizeof(g_bufs[i].name)-1);
            return &g_bufs[i];
        }
    }
    return NULL;
}

static void flushBuf(ScriptBuf* buf) {
    if (!buf || buf->count == 0) return;
    char path[256];
    snprintf(path, sizeof(path), "/sdcard/%s", buf->name);
    FILE* f = fopen(path, "a");
    if (f) {
        for (int i = 0; i < buf->count; i++)
            fprintf(f, "%s\n", buf->lines[i]);
        fclose(f);
    }
    buf->count = 0;
}

static void appendToBuf(const char* scriptPath, const char* msg) {
    pthread_mutex_lock(&g_mutex);
    ScriptBuf* buf = getOrCreateBuf(scriptPath);
    if (buf) {
        strncpy(buf->lines[buf->count], msg, LINE_LEN-1);
        buf->count++;
        if (buf->count >= BUF_LINES)
            flushBuf(buf);
    }
    pthread_mutex_unlock(&g_mutex);
}

// Flush semua buffer ke disk — dipanggil dari luar kalau mau
static void flushAll() {
    pthread_mutex_lock(&g_mutex);
    for (int i = 0; i < MAX_SCRIPTS; i++)
        if (g_bufs[i].used) flushBuf(&g_bufs[i]);
    pthread_mutex_unlock(&g_mutex);
}

static void writeMainLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// ── Filter: apakah source adalah script user? ─────────────────
// Hanya log file .lua di folder monetloader / moonloader
static bool isUserScript(const char* src) {
    if (!src) return false;
    if (src[0] == '=') return false;           // =[C] atau =[string]
    if (src[0] == '?') return false;            // unknown
    // Hanya yang ada path .lua
    if (!strstr(src, ".lua")) return false;
    // Skip internal chunks tanpa path
    if (src[0] != '@' && src[0] != '/') return false;
    return true;
}

// ── Fungsi sensitif ──────────────────────────────────────────
static const char* SENSITIVE_FUNCS[] = {
    "getKeyState","isKeyDown","isKeyPressed","getKey","onKeyDown",
    "socket","connect","send","http","request",
    "sampSendChat","sampSendCommand",
    "loadstring","load","dofile","loadfile",
    "rawget","rawset",
    "base64","encode","decode",
    NULL
};

static bool isSensitive(const char* name) {
    if (!name) return false;
    for (int i = 0; SENSITIVE_FUNCS[i]; i++)
        if (strstr(name, SENSITIVE_FUNCS[i])) return true;
    return false;
}

// ── Lua debug hook ─────────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
void LuaDebugger_hook(lua_State* L, lua_Debug* ar) {
    if (!g_getinfo) return;
    g_getinfo(L, "nSl", ar);

    const char* src  = ar->source ? ar->source : "?";
    const char* name = ar->name   ? ar->name   : "(anon)";
    bool sensitive   = isSensitive(name);

    // Log ke per-script buffer hanya untuk user scripts
    if (isUserScript(src)) {
        char buf[LINE_LEN];
        const char* ev = (ar->event == 0) ? "CALL" : "RET ";
        if (sensitive) {
            snprintf(buf, sizeof(buf), "[%s][⚠ SENSITIVE] %s | line %d",
                ev, name, ar->currentline);
        } else {
            snprintf(buf, sizeof(buf), "[%s] %s | line %d",
                ev, name, ar->currentline);
        }
        appendToBuf(src, buf);
    }

    // Log sensitive ke main log + cari caller
    if (sensitive) {
        char buf[512];
        snprintf(buf, sizeof(buf), "[⚠][%s] %s | %s:%d",
            (ar->event==0)?"CALL":"RET ", name, src, ar->currentline);
        writeMainLog(buf);

        if (g_getstack) {
            lua_Debug caller;
            memset(&caller, 0, sizeof(caller));
            if (g_getstack(L, 1, &caller) && g_getinfo(L, "nSl", &caller)) {
                snprintf(buf, sizeof(buf), "  └─ dari: %s:%d (%s)",
                    caller.source ? caller.source : "?",
                    caller.currentline,
                    caller.name ? caller.name : "(anon)");
                writeMainLog(buf);
            }
        }
    }
}

// ── GOT hook: luaL_newstate ──────────────────────────────────
extern "C" __attribute__((visibility("default")))
lua_State* LuaDebugger_newstate_hook(void) {
    lua_State* L = g_orig_newstate();
    if (L) {
        void* hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_hook");
        if (hookFn && g_sethook) {
            g_sethook(L, (lua_Hook)hookFn, LUA_MASKCALL | LUA_MASKRET, 0);
            char buf[96];
            snprintf(buf, sizeof(buf), "[HOOK] State 0x%x hooked", (unsigned int)L);
            writeMainLog(buf);
        }
    }
    return L;
}

// ── Flush thread: flush buffer tiap 3 detik ──────────────────
static void* flushThread(void*) {
    while (true) {
        sleep(3);
        flushAll();
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
        writeMainLog(buf);
        return true;
    }
    return false;
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeMainLog("=== LuaDebugger START ===");

    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    memset(g_bufs, 0, sizeof(g_bufs));

    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeMainLog("[Step2] monet FAILED"); return; }

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeMainLog("[Step3] luajit FAILED"); return; }

    g_orig_newstate = (luaL_newstate_t)dlsym(luajitHandle, "luaL_newstate");
    g_sethook       = (lua_sethook_t)  dlsym(luajitHandle, "lua_sethook");
    g_getinfo       = (lua_getinfo_t)  dlsym(luajitHandle, "lua_getinfo");
    g_getstack      = (lua_getstack_t) dlsym(luajitHandle, "lua_getstack");

    if (!g_orig_newstate || !g_sethook || !g_getinfo) {
        writeMainLog("[Step3] symbol FAILED"); return;
    }

    char selfPath[512] = {0};
    getSelfPath(selfPath, sizeof(selfPath));
    if (!selfPath[0]) strcpy(selfPath, "libLuaDebugger.so");

    void* selfHandle = dlopen(selfPath, RTLD_NOW | RTLD_GLOBAL);
    if (!selfHandle) { writeMainLog("[Self] dlopen FAILED"); return; }

    void* hookFn = dlsym(selfHandle, "LuaDebugger_newstate_hook");
    if (!hookFn) hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_newstate_hook");
    if (!hookFn) { writeMainLog("[Self] hook symbol FAILED"); return; }

    uintptr_t hookFn_thumb = ((uintptr_t)hookFn & ~1u) | 1u;
    uintptr_t monetBase = getLibBase("libmonetloader.so");
    if (!monetBase) { writeMainLog("[GOT] base FAILED"); return; }

    if (patchGOT(monetBase, "luaL_newstate", (void*)hookFn_thumb)) {
        writeMainLog("[GOT] Patch SUCCESS");

        // Start flush thread
        pthread_t tid;
        pthread_create(&tid, NULL, flushThread, NULL);
        pthread_detach(tid);
        writeMainLog("[INFO] Flush thread started (setiap 3 detik)");
    }
}
