#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <string>
#include <thread>

// ============================================================================
// Speed.exe (Need for Speed: Underground 1) static addresses.
// Recovered by static reverse engineering (Ghidra) and cross-checked against
// multiple call sites in the game itself. RVAs are relative to the Speed.exe
// module base (image base 0x400000).
//
// Race/world manager (global pointer, RVA 0x3361F8):
//   mgr + 0x18          int    number of car entities
//   mgr + 0x28 + i*4    DWORD  car entity pointer [i]
// Each entity carries a short id at +0x0A. The local player's entity has
// id 0; AI and remote racers use 100+ (verified live in memory). The game's
// own id global at RVA 0x2FBF18 stays -1 in offline play and must not be
// used for the lookup.
//
// Car entity (the object in the manager array):
//   +0x0A        short  entity id (matched against the local player id)
//   +0x3D4       float  speed in m/s (the exact value the HUD speedometer
//                        multiplies by 3.6 for km/h or 2.237 for mph)
//   +0x3F0       int    nitrous capacity in fixed-point units
//                        (0x7FFFFFFF sentinel = no nitrous / infinite)
//   +0x3F4       int    nitrous drain per tick while boosting
//   +0x3F8       int    nitrous current amount in fixed-point units
//   +0x3FC       int    boost-active reference (nonzero while boosting)
// Fixed-point scale in the game code is 0.00025 (4000 units = 1 second of
// boost). The game's own code reads/writes these ints through fild/fistp.
//
// Other globals:
//   RVA 0x3041C4  byte   pause flag (1 = paused), see FUN_004057c0
//   RVA 0x38A3F5  byte   metric units option (1 = HUD shows km/h)
// ============================================================================
namespace game {
    constexpr uintptr_t WORLD_MANAGER_PTR = 0x3361F8;
    constexpr uintptr_t PAUSE_FLAG        = 0x3041C4;

    constexpr intptr_t  ENT_ID            = 0x0A;
    constexpr intptr_t  ENT_SPEED_MS      = 0x3D4;
    constexpr intptr_t  ENT_NITRO_MAX     = 0x3F0;
    constexpr intptr_t  ENT_NITRO_CURRENT = 0x3F8;
    constexpr intptr_t  ENT_NITRO_BOOSTED = 0x3FC;

    constexpr int NITRO_NO_SENTINEL = 0x7FFFFFFF;
    constexpr int MAX_ENTITIES = 8;

    static bool Readable(const void* p, size_t len) {
        return p != nullptr && !IsBadReadPtr(p, len);
    }

    static bool IsGamePaused(uintptr_t base) {
        const uint8_t* flag = reinterpret_cast<const uint8_t*>(base + PAUSE_FLAG);
        return Readable(flag, 1) && *flag == 1;
    }

    // Resolves the local player's car entity for this frame, or 0.
    // The local player is the entity carrying short id 0 (AI/remote use
    // 100+); if the id layout ever differs, fall back to the first entity.
    static uintptr_t FindPlayerEntity(uintptr_t base) {
        uintptr_t* mgrPtr = reinterpret_cast<uintptr_t*>(base + WORLD_MANAGER_PTR);
        if (!Readable(mgrPtr, 4)) return 0;

        uintptr_t mgr = *mgrPtr;
        if (mgr == 0 || !Readable(reinterpret_cast<const void*>(mgr + 0x18), 8)) return 0;

        int count = *reinterpret_cast<int*>(mgr + 0x18);
        if (count <= 0 || count > MAX_ENTITIES) return 0;

        uintptr_t entries = mgr + 0x28;
        if (!Readable(reinterpret_cast<const void*>(entries), count * 4)) return 0;

        uintptr_t first = 0;
        for (int i = 0; i < count; ++i) {
            uintptr_t ent = *reinterpret_cast<uintptr_t*>(entries + i * 4);
            if (ent == 0) continue;
            if (!Readable(reinterpret_cast<const void*>(ent + ENT_ID), 2)) continue;
            if (first == 0) first = ent;
            if (*reinterpret_cast<short*>(ent + ENT_ID) == 0) {
                first = ent;
                break;
            }
        }
        if (first == 0) return 0;
        if (!Readable(reinterpret_cast<const void*>(first + ENT_NITRO_CURRENT), 0x10)) return 0;
        return first;
    }
}

static bool g_fastRefill = false;

static void LoadConfig(const std::wstring& iniPath) {
    wchar_t buffer[8] = { 0 };

    DWORD attrs = GetFileAttributesW(iniPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        FILE* f;
        _wfopen_s(&f, iniPath.c_str(), L"w, ccs=UTF-8");
        if (f) {
            fwprintf(f,
                L"; NFSU Most Wanted Nitrous System Configuration\n"
                L"; ================================================\n"
                L"\n"
                L"[Settings]\n"
                L"\n"
                L"FastRefill    = 0    ; Speeds up nitrous refill and shortens cooldown after use.            (0 = Off, 1 = On)\n"
            );
            fclose(f);
        }
        else {
            g_fastRefill = false;
            return;
        }
    }

    GetPrivateProfileStringW(L"Settings", L"FastRefill", L"0", buffer, 8, iniPath.c_str());
    g_fastRefill = wcstol(buffer, nullptr, 10) != 0;
}

static void NitrousUpdaterThread() {
    HMODULE hGame = GetModuleHandleW(L"Speed.exe");
    if (hGame == nullptr) {
        // Ultimate ASI Loader may run us before Speed.exe is mapped under that name.
        hGame = GetModuleHandleW(nullptr);
    }
    uintptr_t gameBase = reinterpret_cast<uintptr_t>(hGame);
    if (gameBase == 0) return;

    const int updateIntervalMs = 25;
    const DWORD cooldownMs = g_fastRefill ? 1000 : 2000;
    // The game freezes for roughly half a second right after unpausing.
    // Refilling during that freeze shows up as an instant nitrous jump,
    // so hold the refill for 1s total after unpausing.
    const DWORD unpauseBufferMs = 1000;

    int lastNitroValue = -1;
    ULONGLONG lastDecreaseTime = 0;

    ULONGLONG lastUpdateTime = GetTickCount64();
    ULONGLONG gameTime = 0;
    bool wasGamePaused = false;
    ULONGLONG unpauseTime = 0;

    while (true) {
        ULONGLONG now = GetTickCount64();
        ULONGLONG elapsedTime = now - lastUpdateTime;

        if (elapsedTime < updateIntervalMs) {
            Sleep(static_cast<DWORD>(updateIntervalMs - elapsedTime));
            continue;
        }

        bool isGamePaused = game::IsGamePaused(gameBase);

        if (wasGamePaused && !isGamePaused) {
            unpauseTime = now;
        }

        if (!isGamePaused) {
            if (!wasGamePaused) {
                gameTime += elapsedTime;
            }
        }

        lastUpdateTime = now;
        wasGamePaused = isGamePaused;

        if (isGamePaused) {
            Sleep(updateIntervalMs);
            continue;
        }

        if ((now - unpauseTime) < unpauseBufferMs) {
            Sleep(updateIntervalMs);
            continue;
        }

        uintptr_t ent = game::FindPlayerEntity(gameBase);
        if (ent == 0) {
            lastNitroValue = -1;
            Sleep(updateIntervalMs);
            continue;
        }

        const int maxNitro = *reinterpret_cast<int*>(ent + game::ENT_NITRO_MAX);
        if (maxNitro <= 0 || maxNitro == game::NITRO_NO_SENTINEL) {
            // No nitrous equipped on this car.
            lastNitroValue = -1;
            Sleep(updateIntervalMs);
            continue;
        }

        const uintptr_t nitroAddr = ent + game::ENT_NITRO_CURRENT;
        int currentValue = *reinterpret_cast<int*>(nitroAddr);
        if (currentValue < 0 || currentValue > maxNitro) {
            lastNitroValue = -1;
            Sleep(updateIntervalMs);
            continue;
        }

        // The game drains this field while boosting; treat any drop (or an
        // active boost, flagged by the game at +0x3FC) as nitrous usage and
        // restart the refill cooldown.
        const bool boosting = *reinterpret_cast<int*>(ent + game::ENT_NITRO_BOOSTED) != 0;
        if (boosting || (lastNitroValue >= 0 && currentValue < lastNitroValue)) {
            lastDecreaseTime = gameTime;
        }
        lastNitroValue = currentValue;

        // Speed converted to mph. The tuning thresholds below (50-100) were
        // authored for mph, so always use the mph scale regardless of what
        // the HUD displays (the game's km/h option only affects the readout).
        const float speedMs = *reinterpret_cast<float*>(ent + game::ENT_SPEED_MS);
        const int carSpeed = static_cast<int>(speedMs * 2.237f);

        int minSpeed = g_fastRefill ? 20 : 50;
        int maxSpeed = g_fastRefill ? 140 : 100;
        double minTime = g_fastRefill ? 35.0 : 50.0;
        double maxTime = g_fastRefill ? 15.0 : 30.0;

        if (carSpeed < minSpeed) {
            Sleep(updateIntervalMs);
            continue;
        }

        int clampedSpeed = std::max(minSpeed, std::min(carSpeed, maxSpeed));
        double t = (clampedSpeed - minSpeed) / static_cast<double>(maxSpeed - minSpeed);
        double refillTime = minTime + t * (maxTime - minTime);

        // Scale by the real elapsed time so a full bar takes refillTime
        // seconds regardless of how often the update loop actually runs
        // (Sleep granularity makes it ~32 Hz instead of a nominal 40 Hz).
        double dtSec = elapsedTime / 1000.0;
        if (dtSec > 0.25) dtSec = 0.25;  // ignore huge gaps (loading, stalls)
        int refillIncrement = static_cast<int>(maxNitro * dtSec / refillTime);
        if (refillIncrement < 1) refillIncrement = 1;

        if ((gameTime - lastDecreaseTime) >= cooldownMs && currentValue < maxNitro) {
            *reinterpret_cast<int*>(nitroAddr) = std::min(currentValue + refillIncrement, maxNitro);
        }

        Sleep(updateIntervalMs);
    }
}

static DWORD WINAPI MainThread(HMODULE hModule) {
    wchar_t iniPath[MAX_PATH];
    GetModuleFileNameW(hModule, iniPath, MAX_PATH);
    *wcsrchr(iniPath, L'\\') = 0;
    wcscat_s(iniPath, L"\\NFSUMostWantedNitrousSystem.ini");

    LoadConfig(iniPath);

    std::thread updater(NitrousUpdaterThread);
    updater.detach();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}
