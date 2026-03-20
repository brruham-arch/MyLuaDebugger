#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/time.h>
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
typedef int        (*lua_getstack_t)(lua_State*, int, lua_Debug*);
typedef int        (*lua_gettop_t)(lua_State*);
typedef int        (*lua_type_t)(lua_State*, int);
typedef const char*(*lua_tostring_t)(lua_State*, int);
typedef double     (*lua_tonumber_t)(lua_State*, int);
typedef int        (*lua_toboolean_t)(lua_State*, int);
typedef const char*(*lua_typename_t)(lua_State*, int);

#define LUA_MASKCALL  1
#define LUA_MASKRET   2
#define LUA_MASKLINE  4

#define LUA_TNIL      0
#define LUA_TBOOLEAN  1
#define LUA_TNUMBER   3
#define LUA_TSTRING   4
#define LUA_TTABLE    5
#define LUA_TFUNCTION 6

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
static lua_gettop_t    g_gettop        = NULL;
static lua_type_t      g_type          = NULL;
static lua_tostring_t  g_tostring      = NULL;
static lua_tonumber_t  g_tonumber      = NULL;
static lua_toboolean_t g_toboolean     = NULL;
static lua_typename_t  g_typename      = NULL;

// ── Config ───────────────────────────────────────────────────
static char  g_target[128]   = {0};  // nama file target, e.g. "animmmloger.lua"
static bool  g_config_loaded = false;

static void loadConfig() {
    FILE* f = fopen("/sdcard/luadbg_config.txt", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // strip newline
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "target=", 7) == 0) {
            strncpy(g_target, line + 7, sizeof(g_target)-1);
        }
    }
    fclose(f);
    g_config_loaded = true;
}

// ── Buffer JSON ───────────────────────────────────────────────
#define JSON_BUF_SIZE  300
#define JSON_LINE_LEN  1024

static char    g_json_buf[JSON_BUF_SIZE][JSON_LINE_LEN];
static int     g_json_count  = 0;
static bool    g_json_dirty  = false;
static bool    g_file_opened = false;  // apakah array JSON sudah dibuka
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// Escape string untuk JSON
static void jsonEscape(const char* src, char* dst, size_t dstLen) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dstLen-2; i++) {
        switch (src[i]) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"';  break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r';  break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
            default:
                if ((unsigned char)src[i] < 0x20) {
                    j += snprintf(dst+j, dstLen-j, "\\u%04x", (unsigned char)src[i]);
                } else {
                    dst[j++] = src[i];
                }
        }
    }
    dst[j] = '\0';
}

static void flushJSON() {
    if (!g_json_dirty || g_json_count == 0) return;

    FILE* f = fopen("/sdcard/luadbg_deep.json", g_file_opened ? "a" : "w");
    if (!f) return;

    if (!g_file_opened) {
        fprintf(f, "[\n");
        g_file_opened = true;
    }

    for (int i = 0; i < g_json_count; i++) {
        fprintf(f, "%s", g_json_buf[i]);
    }
    fclose(f);
    g_json_count = 0;
    g_json_dirty = false;
}

static void addJSONEvent(const char* json) {
    pthread_mutex_lock(&g_mutex);
    if (g_json_count < JSON_BUF_SIZE) {
        strncpy(g_json_buf[g_json_count++], json, JSON_LINE_LEN-1);
        g_json_dirty = true;
        if (g_json_count >= JSON_BUF_SIZE) flushJSON();
    }
    pthread_mutex_unlock(&g_mutex);
}

// ── Ambil timestamp ms ────────────────────────────────────────
static long long getTimeMs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// ── Ambil argumen dari Lua stack sebagai string JSON ──────────
static void getArgs(lua_State* L, char* out, size_t outLen) {
    if (!g_gettop || !g_type || !g_typename) {
        strncpy(out, "[]", outLen); return;
    }
    int top = g_gettop(L);
    if (top <= 0) { strncpy(out, "[]", outLen); return; }

    char tmp[512] = "[";
    for (int i = 1; i <= top && i <= 8; i++) {  // max 8 args
        int t = g_type(L, i);
        char val[128] = "null";
        char esc[200];

        switch (t) {
            case LUA_TNIL:
                strncpy(val, "null", sizeof(val)); break;
            case LUA_TBOOLEAN:
                snprintf(val, sizeof(val), "%s",
                    g_toboolean(L, i) ? "true" : "false"); break;
            case LUA_TNUMBER:
                snprintf(val, sizeof(val), "%g", g_tonumber(L, i)); break;
            case LUA_TSTRING: {
                const char* s = g_tostring(L, i);
                if (s) {
                    jsonEscape(s, esc, sizeof(esc));
                    snprintf(val, sizeof(val), "\"%s\"", esc);
                } else {
                    strncpy(val, "\"\"", sizeof(val));
                }
                break;
            }
            default: {
                const char* tn = g_typename ? g_typename(L, t) : "?";
                snprintf(val, sizeof(val), "\"[%s]\"", tn ? tn : "?");
                break;
            }
        }

        if (i > 1) strncat(tmp, ",", sizeof(tmp)-strlen(tmp)-1);
        strncat(tmp, val, sizeof(tmp)-strlen(tmp)-1);
    }
    strncat(tmp, "]", sizeof(tmp)-strlen(tmp)-1);
    strncpy(out, tmp, outLen-1);
}

// ── Ambil stack trace sebagai JSON array ─────────────────────
static void getStackTrace(lua_State* L, char* out, size_t outLen) {
    if (!g_getstack || !g_getinfo) {
        strncpy(out, "[]", outLen); return;
    }
    char tmp[1024] = "[";
    bool first = true;
    for (int level = 1; level <= 6; level++) {
        lua_Debug frame;
        memset(&frame, 0, sizeof(frame));
        if (!g_getstack(L, level, &frame)) break;
        if (!g_getinfo(L, "nSl", &frame)) break;

        char srcEsc[128], nameEsc[64];
        jsonEscape(frame.source ? frame.source : "?", srcEsc, sizeof(srcEsc));
        jsonEscape(frame.name   ? frame.name   : "(anon)", nameEsc, sizeof(nameEsc));

        char entry[256];
        snprintf(entry, sizeof(entry),
            "%s{\"func\":\"%s\",\"src\":\"%s\",\"line\":%d}",
            first ? "" : ",", nameEsc, srcEsc, frame.currentline);
        strncat(tmp, entry, sizeof(tmp)-strlen(tmp)-1);
        first = false;
    }
    strncat(tmp, "]", sizeof(tmp)-strlen(tmp)-1);
    strncpy(out, tmp, outLen-1);
}

// ── Cek apakah event ini dari target script ───────────────────
static bool isTarget(lua_State* L, const char* src) {
    if (!g_target[0]) return false;

    // Cek source langsung
    if (src && strstr(src, g_target)) return true;

    // Cek caller di stack
    if (g_getstack) {
        for (int level = 1; level <= 4; level++) {
            lua_Debug frame;
            memset(&frame, 0, sizeof(frame));
            if (!g_getstack(L, level, &frame)) break;
            if (!g_getinfo(L, "S", &frame)) break;
            if (frame.source && strstr(frame.source, g_target)) return true;
        }
    }
    return false;
}

// ── Lua hook: DEEP mode untuk target script ───────────────────
extern "C" __attribute__((visibility("default")))
void LuaDebugger_hook(lua_State* L, lua_Debug* ar) {
    if (!g_getinfo || !g_target[0]) return;
    g_getinfo(L, "nSl", ar);

    const char* src = ar->source ? ar->source : "?";

    if (!isTarget(L, src)) return;

    const char* evName = "unknown";
    if (ar->event == 0) evName = "call";
    else if (ar->event == 1) evName = "return";
    else if (ar->event == 2) evName = "line";

    char args[512]   = "[]";
    char stack[1024] = "[]";
    char srcEsc[200], nameEsc[64];

    jsonEscape(src, srcEsc, sizeof(srcEsc));
    jsonEscape(ar->name ? ar->name : "(anon)", nameEsc, sizeof(nameEsc));

    // Argumen hanya untuk CALL event
    if (ar->event == 0) getArgs(L, args, sizeof(args));

    // Stack trace
    getStackTrace(L, stack, sizeof(stack));

    char json[JSON_LINE_LEN];
    snprintf(json, sizeof(json),
        "  {\"t\":%lld,\"event\":\"%s\",\"func\":\"%s\",\"namewhat\":\"%s\","
        "\"src\":\"%s\",\"line\":%d,\"args\":%s,\"stack\":%s},\n",
        getTimeMs(),
        evName,
        nameEsc,
        ar->namewhat ? ar->namewhat : "",
        srcEsc,
        ar->currentline,
        args,
        stack
    );

    addJSONEvent(json);
}

// ── GOT hook ─────────────────────────────────────────────────
extern "C" __attribute__((visibility("default")))
lua_State* LuaDebugger_newstate_hook(void) {
    lua_State* L = g_orig_newstate();
    if (L && g_sethook) {
        void* hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_hook");
        if (hookFn) {
            // CALL + RET + LINE untuk deep mode
            g_sethook(L, (lua_Hook)hookFn,
                LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE, 0);
        }
    }
    return L;
}

// ── Flush thread ─────────────────────────────────────────────
static void* flushThread(void*) {
    while (true) {
        sleep(3);
        pthread_mutex_lock(&g_mutex);
        flushJSON();
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
        snprintf(buf, sizeof(buf), "[GOT] patched '%s'", symName);
        writeLog(buf); return true;
    }
    return false;
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger Deep loaded!");
    writeLog("=== LuaDebugger DEEP START ===");

    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    // Baca config
    loadConfig();

    if (!g_target[0]) {
        writeLog("[CONFIG] target tidak diset!");
        writeLog("[CONFIG] Buat file: /sdcard/luadbg_config.txt");
        writeLog("[CONFIG] Isi: target=namaScript.lua");
        // Tetap jalan tapi tidak ada yang di-log
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "[CONFIG] Target: %s", g_target);
        writeLog(buf);
    }

    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[LuaJIT] FAILED"); return; }

    g_orig_newstate = (luaL_newstate_t)dlsym(luajitHandle, "luaL_newstate");
    g_sethook       = (lua_sethook_t)  dlsym(luajitHandle, "lua_sethook");
    g_getinfo       = (lua_getinfo_t)  dlsym(luajitHandle, "lua_getinfo");
    g_getstack      = (lua_getstack_t) dlsym(luajitHandle, "lua_getstack");
    g_gettop        = (lua_gettop_t)   dlsym(luajitHandle, "lua_gettop");
    g_type          = (lua_type_t)     dlsym(luajitHandle, "lua_type");
    g_tostring      = (lua_tostring_t) dlsym(luajitHandle, "lua_tolstring");
    g_tonumber      = (lua_tonumber_t) dlsym(luajitHandle, "lua_tonumber");
    g_toboolean     = (lua_toboolean_t)dlsym(luajitHandle, "lua_toboolean");
    g_typename      = (lua_typename_t) dlsym(luajitHandle, "lua_typename");

    if (!g_orig_newstate || !g_sethook || !g_getinfo) {
        writeLog("[LuaJIT] symbol FAILED"); return;
    }

    // Load monet
    dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);

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
        writeLog("[INFO] Output: /sdcard/luadbg_deep.json");

        pthread_t tid;
        pthread_create(&tid, NULL, flushThread, NULL);
        pthread_detach(tid);
    }
}
