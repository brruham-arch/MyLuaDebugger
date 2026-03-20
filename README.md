# MyLuaDebugger

AML mod untuk mendebug aktivitas script Lua di SA-MP Android (MoNetLoader).

## Build Status
Dikompile via GitHub Actions dengan NDK r25c, target `armeabi-v7a`.

## Roadmap

- [x] Step 1 — `.so` load + file log konfirmasi
- [ ] Step 2 — `dlopen` libmonetloader.so
- [ ] Step 3 — Cari `lua_State*`
- [ ] Step 4 — Pasang `lua_sethook`
- [ ] Step 5 — Log output lengkap
- [ ] Step 6 — ImGui overlay (opsional)

## Cara Test (Step 1)

1. Download `libLuaDebugger.so` dari Actions artifact
2. Taruh di folder mod AML
3. Launch game
4. Cek hasil: `cat /sdcard/luadbg.log`

Kalau muncul `[LuaDebugger] .so loaded successfully` → Step 1 berhasil.
