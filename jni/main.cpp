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

// Replacement luaL_newstate — dipanggil via GOT patch
static lua_State* my_newstate(void) {
    lua_State* L = g_orig_newstate();
    if (!g_L && L) {
        g_L = L;
        char buf[128];
        snprintf(buf, sizeof(buf), "[GOT] lua_State* CAPTURED = 0x%x", (unsigned int)L);
        writeLog(buf);
        LOGI("%s", buf);
    }
    return L;
}

// Dapatkan base address library dari /proc/self/maps
static uintptr_t getLibBase(const char* name) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name) && strstr(line, "r--p")) {
            base = (uintptr_t)strtoul(line, NULL, 16);
            break;
        }
    }
    // fallback: ambil yang pertama muncul
    if (!base) {
        rewind(f);
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, name)) {
                base = (uintptr_t)strtoul(line, NULL, 16);
                break;
            }
        }
    }
    fclose(f);
    return base;
}

// GOT patch: cari & ganti entry luaL_newstate di libmonetloader.so
static bool patchGOT(uintptr_t base, const char* symName, void* newFunc, void** origFunc) {
    if (!base) return false;

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)base;
    if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E') {
        writeLog("[GOT] ELF magic invalid");
        return false;
    }

    Elf32_Phdr* phdr = (Elf32_Phdr*)(base + ehdr->e_phoff);

    // Cari PT_DYNAMIC
    Elf32_Dyn* dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf32_Dyn*)(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) { writeLog("[GOT] PT_DYNAMIC not found"); return false; }

    // Parse dynamic section
    Elf32_Sym*  symtab   = NULL;
    const char* strtab   = NULL;
    Elf32_Rel*  jmprel   = NULL;
    size_t      jmprel_sz = 0;

    for (Elf32_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:  symtab    = (Elf32_Sym*) (base + d->d_un.d_ptr); break;
            case DT_STRTAB:  strtab    = (const char*)(base + d->d_un.d_ptr); break;
            case DT_JMPREL:  jmprel    = (Elf32_Rel*) (base + d->d_un.d_ptr); break;
            case DT_PLTRELSZ: jmprel_sz = d->d_un.d_val; break;
        }
    }

    if (!symtab || !strtab || !jmprel) {
        writeLog("[GOT] symtab/strtab/jmprel NULL");
        return false;
    }

    size_t count = jmprel_sz / sizeof(Elf32_Rel);
    char buf[256];
    snprintf(buf, sizeof(buf), "[GOT] scanning %zu PLT relocations", count);
    writeLog(buf);

    for (size_t i = 0; i < count; i++) {
        uint32_t sym_idx = ELF32_R_SYM(jmprel[i].r_info);
        const char* name = strtab + symtab[sym_idx].st_name;

        if (strcmp(name, symName) == 0) {
            // Ketemu!
            uint32_t* got_entry = (uint32_t*)(base + jmprel[i].r_offset);

            snprintf(buf, sizeof(buf), "[GOT] found '%s' at GOT=0x%x val=0x%x",
                symName, (unsigned int)got_entry, *got_entry);
            writeLog(buf);

            // Simpan original
            if (origFunc) *origFunc = (void*)(uintptr_t)*got_entry;

            // mprotect page jadi writable
            uintptr_t page    = (uintptr_t)got_entry & ~(getpagesize()-1);
            if (mprotect((void*)page, getpagesize(), PROT_READ | PROT_WRITE) != 0) {
                writeLog("[GOT] mprotect FAILED");
                return false;
            }

            // Patch!
            *got_entry = (uint32_t)(uintptr_t)newFunc;

            // Restore protection
            mprotect((void*)page, getpagesize(), PROT_READ);

            snprintf(buf, sizeof(buf), "[GOT] patched! new=0x%x", (unsigned int)newFunc);
            writeLog(buf);
            return true;
        }
    }

    writeLog("[GOT] symbol not found in PLT");
    return false;
}

__attribute__((constructor))
static void onLoad() {
    LOGI("LuaDebugger loaded!");
    writeLog("[LuaDebugger] .so loaded successfully");

    static int initialized = 0;
    if (initialized) { writeLog("[WARN] double load, skip"); return; }
    initialized = 1;

    // Load monet
    void* monetHandle = dlopen("libmonetloader.so", RTLD_NOW | RTLD_GLOBAL);
    if (!monetHandle) { writeLog("[Step2] dlopen monet FAILED"); return; }
    writeLog("[Step2] dlopen libmonetloader.so SUCCESS");

    // Load luajit — kita perlu original function pointer
    void* luajitHandle = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_GLOBAL);
    if (!luajitHandle) { writeLog("[Step3] dlopen luajit FAILED"); return; }
    writeLog("[Step3] dlopen libluajit-5.1.so SUCCESS");

    // Simpan original dari luajit langsung (bukan dari GOT)
    g_orig_newstate = (luaL_newstate_t)dlsym(luajitHandle, "luaL_newstate");
    if (!g_orig_newstate) { writeLog("[Step3] luaL_newstate symbol FAILED"); return; }

    char buf[256];
    snprintf(buf, sizeof(buf), "[Step3] orig luaL_newstate=0x%x", (unsigned int)g_orig_newstate);
    writeLog(buf);

    // Dapatkan base libmonetloader.so
    uintptr_t monetBase = getLibBase("libmonetloader.so");
    snprintf(buf, sizeof(buf), "[GOT] libmonetloader.so base=0x%x", (unsigned int)monetBase);
    writeLog(buf);

    if (!monetBase) { writeLog("[GOT] base FAILED"); return; }

    // Patch GOT monet untuk luaL_newstate
    void* dummy = NULL; // kita sudah punya orig dari dlsym langsung
    bool ok = patchGOT(monetBase, "luaL_newstate", (void*)my_newstate, &dummy);
    if (ok) {
        writeLog("[GOT] Patch SUCCESS — no Dobby needed!");
    } else {
        writeLog("[GOT] Patch FAILED");
    }
}
