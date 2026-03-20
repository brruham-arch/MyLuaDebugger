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

typedef struct lua_State lua_State;
typedef lua_State* (*luaL_newstate_t)(void);

static lua_State*      g_L             = NULL;
static luaL_newstate_t g_orig_newstate = NULL;

static void writeLog(const char* msg) {
    FILE* f = fopen("/sdcard/luadbg.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
}

// Fungsi ini akan dipanggil via GOT hook
// extern "C" agar tidak mangle, visibility default agar di-export
extern "C" __attribute__((visibility("default")))
lua_State* LuaDebugger_newstate_hook(void) {
    lua_State* L = g_orig_newstate();
    if (!g_L && L) {
        g_L = L;
        char buf[128];
        snprintf(buf, sizeof(buf), "[HOOK] lua_State* CAPTURED = 0x%x", (unsigned int)L);
        writeLog(buf);
        LOGI("%s", buf);
    }
    return L;
}

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

// Cari path .so kita sendiri dari /proc/self/maps
static bool getSelfPath(char* out, size_t sz) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libLuaDebugger.so")) continue;
        // Format: addr-addr perms offset dev inode path
        char* path = strrchr(line, '/');
        if (!path) continue;
        path = strstr(line, "/data");
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
            dyn = (Elf32_Dyn*)(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) { writeLog("[GOT] no PT_DYNAMIC"); return false; }

    Elf32_Sym* symtab = NULL; const char* strtab = NULL;
    Elf32_Rel* jmprel = NULL; size_t jmprel_sz = 0;
    for (Elf32_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB)   symtab    = (Elf32_Sym*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_STRTAB)   strtab    = (const char*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_JMPREL)   jmprel    = (Elf32_Rel*)(base + d->d_un.d_ptr);
        if (d->d_tag == DT_PLTRELSZ) jmprel_sz = d->d_un.d_val;
    }
    if (!symtab || !strtab || !jmprel) { writeLog("[GOT] null sections"); return false; }

    for (size_t i = 0; i < jmprel_sz / sizeof(Elf32_Rel); i++) {
        uint32_t sym_idx = ELF32_R_SYM(jmprel[i].r_info);
        if (strcmp(strtab + symtab[sym_idx].st_name, symName) != 0) continue;

        uint32_t* got = (uint32_t*)(base + jmprel[i].r_offset);
        snprintf(buf, sizeof(buf), "[GOT] found '%s' at 0x%x cur=0x%x", symName, (unsigned int)got, *got);
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
    if (!g_orig_newstate) { writeLog("[Step3] luaL_newstate FAILED"); return; }

    char buf[512];
    snprintf(buf, sizeof(buf), "[Step3] orig luaL_newstate=0x%x", (unsigned int)g_orig_newstate);
    writeLog(buf);

    // Kunci: dlopen diri kita sendiri via SYSTEM LINKER
    // sehingga hook function ada di properly-executable region
    char selfPath[512] = {0};
    if (!getSelfPath(selfPath, sizeof(selfPath))) {
        writeLog("[Self] getSelfPath FAILED — fallback ke nama saja");
        strcpy(selfPath, "libLuaDebugger.so");
    }
    snprintf(buf, sizeof(buf), "[Self] path=%s", selfPath);
    writeLog(buf);

    void* selfHandle = dlopen(selfPath, RTLD_NOW | RTLD_GLOBAL);
    if (!selfHandle) {
        const char* err = dlerror();
        snprintf(buf, sizeof(buf), "[Self] dlopen FAILED: %s", err ? err : "?");
        writeLog(buf);
        return;
    }
    writeLog("[Self] dlopen self SUCCESS");

    // Ambil hook function — coba dari handle dulu, fallback ke RTLD_DEFAULT
    void* hookFn = dlsym(selfHandle, "LuaDebugger_newstate_hook");
    if (!hookFn) {
        writeLog("[Self] dlsym(handle) FAILED, coba RTLD_DEFAULT...");
        hookFn = dlsym(RTLD_DEFAULT, "LuaDebugger_newstate_hook");
    }
    if (!hookFn) {
        writeLog("[Self] LuaDebugger_newstate_hook symbol FAILED semua cara");
        return;
    }
    snprintf(buf, sizeof(buf), "[Self] hook fn=0x%x", (unsigned int)hookFn);
    writeLog(buf);

    // Thumb bit
    uintptr_t hookFn_thumb = ((uintptr_t)hookFn & ~1u) | 1u;
    snprintf(buf, sizeof(buf), "[Self] hook fn_thumb=0x%x", (unsigned int)hookFn_thumb);
    writeLog(buf);

    uintptr_t monetBase = getLibBase("libmonetloader.so");
    snprintf(buf, sizeof(buf), "[GOT] monet base=0x%x", (unsigned int)monetBase);
    writeLog(buf);
    if (!monetBase) { writeLog("[GOT] base FAILED"); return; }

    if (patchGOT(monetBase, "luaL_newstate", (void*)hookFn_thumb)) {
        writeLog("[GOT] Patch SUCCESS — menunggu luaL_newstate...");
    } else {
        writeLog("[GOT] Patch FAILED");
    }
}
