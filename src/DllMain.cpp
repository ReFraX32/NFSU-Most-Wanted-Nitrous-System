#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <string>

#pragma comment(lib, "psapi.lib")

struct PointerChain {
    DWORD baseOffset = 0;
    std::vector<DWORD> offsets;
};

static bool g_fastRefill = false;

static PointerChain g_currentSpeedPointer;
static bool g_hasValidSpeedPointer = false;
static ULONGLONG g_lastPointerCheckTime = 0;
static const ULONGLONG POINTER_CHECK_INTERVAL_MS = 10000;

static uintptr_t ResolvePointer(uintptr_t base, const PointerChain& chain) {
    uintptr_t addr = base + chain.baseOffset;
    for (size_t i = 0; i < chain.offsets.size(); ++i) {
        if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(uintptr_t))) {
            return 0;
        }
        addr = *reinterpret_cast<uintptr_t*>(addr);
        addr += chain.offsets[i];
    }
    return addr;
}

static uintptr_t GetModuleBaseAddress(const wchar_t* moduleName) {
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, MAX_PATH)) {
                if (_wcsicmp(szModName, moduleName) == 0) {
                    return reinterpret_cast<uintptr_t>(hMods[i]);
                }
            }
        }
    }
    return 0;
}

static bool IsGamePaused(uintptr_t gameBase) {
    uintptr_t pauseFlagAddr = gameBase + 0x3041C4;
    if (IsBadReadPtr(reinterpret_cast<void*>(pauseFlagAddr), sizeof(short))) {
        return false;
    }
    short pauseValue = *reinterpret_cast<short*>(pauseFlagAddr);
    return pauseValue == 1;
}

static int GetSpeedValue(uintptr_t gameBase, const PointerChain& speedPointer) {
    uintptr_t speedAddr = ResolvePointer(gameBase, speedPointer);
    if (speedAddr != 0 && !IsBadReadPtr(reinterpret_cast<void*>(speedAddr), sizeof(int))) {
        return *reinterpret_cast<int*>(speedAddr);
    }
    return -999;
}

static bool IsPointerValid(uintptr_t gameBase, const PointerChain& speedPointer) {
    uintptr_t speedAddr = ResolvePointer(gameBase, speedPointer);
    return (speedAddr != 0 && !IsBadReadPtr(reinterpret_cast<void*>(speedAddr), sizeof(int)));
}

static PointerChain GetDefaultSpeedPointer() {
    return { 0x33D7F4, {0x0, 0x2C, 0x0, 0x0, 0x0, 0x24, 0x58} };
}

static PointerChain SelectBestSpeedPointer(uintptr_t gameBase) {
    PointerChain speed1 = { 0x33D7F4, {0x0, 0x2C, 0x0, 0x0, 0x0, 0x24, 0x58} };
    PointerChain speed2 = { 0x32D1D4, {0x54, 0x44, 0x8, 0x0, 0x76C, 0x24, 0x58} };
    PointerChain speed3 = { 0x33D7F4, {0xC, 0x20, 0xD4, 0x54, 0x44, 0x0, 0x70} };
    PointerChain speed4 = { 0x33D7F4, {0x0, 0x2C, 0x0, 0x8, 0x0, 0x1C, 0x58} };

    bool valid1 = IsPointerValid(gameBase, speed1);
    bool valid2 = IsPointerValid(gameBase, speed2);
    bool valid3 = IsPointerValid(gameBase, speed3);
    bool valid4 = IsPointerValid(gameBase, speed4);

    int val1 = valid1 ? GetSpeedValue(gameBase, speed1) : -999;
    int val2 = valid2 ? GetSpeedValue(gameBase, speed2) : -999;
    int val3 = valid3 ? GetSpeedValue(gameBase, speed3) : -999;
    int val4 = valid4 ? GetSpeedValue(gameBase, speed4) : -999;

    bool hasValidPointers = valid1 || valid2 || valid3 || valid4;
    if (!hasValidPointers) {
        return GetDefaultSpeedPointer();
    }

    if (valid1) {

        if (valid2 && val1 == val2) {
            return speed1;
        }

        if (valid2 && valid3 && val1 != val2 && val2 == val3) {
            return speed2;
        }

        if (!valid2) {
            if (valid3 && valid4) {
                if (val1 == val4) {
                }
                if (val3 == val4) {
                }
            }
        }

        return speed1;
    }

    if (valid2) {
        return speed2;
    }

    if (valid3) {
        return speed3;
    }

    if (valid4) {
        return speed4;
    }

    return GetDefaultSpeedPointer();
}

static void UpdateSpeedPointerDynamic(uintptr_t gameBase, ULONGLONG currentTime) {
    if (currentTime - g_lastPointerCheckTime < POINTER_CHECK_INTERVAL_MS) {
        return;
    }

    g_lastPointerCheckTime = currentTime;

    bool currentPointerStillValid = g_hasValidSpeedPointer &&
        IsPointerValid(gameBase, g_currentSpeedPointer);

    if (!currentPointerStillValid) {
        g_currentSpeedPointer = SelectBestSpeedPointer(gameBase);
        g_hasValidSpeedPointer = IsPointerValid(gameBase, g_currentSpeedPointer);
        return;
    }

    PointerChain bestPointer = SelectBestSpeedPointer(gameBase);

    if (bestPointer.baseOffset != g_currentSpeedPointer.baseOffset ||
        bestPointer.offsets != g_currentSpeedPointer.offsets) {

        if (IsPointerValid(gameBase, bestPointer)) {
            g_currentSpeedPointer = bestPointer;
            g_hasValidSpeedPointer = true;
        }
    }
}

static int GetCurrentSpeed(uintptr_t gameBase, ULONGLONG currentTime) {
    UpdateSpeedPointerDynamic(gameBase, currentTime);

    if (!g_hasValidSpeedPointer) {
        return -999;
    }

    int speed = GetSpeedValue(gameBase, g_currentSpeedPointer);

    if (speed == -999) {
        g_hasValidSpeedPointer = false;
    }

    return speed;
}

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
    uintptr_t gameBase = GetModuleBaseAddress(L"Speed.exe");
    if (gameBase == 0) return;

    g_currentSpeedPointer = GetDefaultSpeedPointer();
    g_hasValidSpeedPointer = false;
    g_lastPointerCheckTime = 0;

    PointerChain nitrousChain = { 0x31A8C0, {0x2C, 0x34, 0x20, 0x8, 0x4, 0x30, 0x3B8} };

    PointerChain maxNitrousPointer = { 0x335F78, {0x50, 0x4, 0x34, 0x4, 0x1C, 0x1C, 0x3B0} };

    const int updateIntervalMs = 25;
    const DWORD cooldownMs = g_fastRefill ? 1000 : 2000;
    const DWORD unpauseBufferMs = 500;

    std::unordered_map<uintptr_t, int> lastValues;
    std::unordered_map<uintptr_t, ULONGLONG> cooldownTimestamps;
    std::unordered_map<uintptr_t, int> maxValues;

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

        bool isGamePaused = IsGamePaused(gameBase);

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

        uintptr_t maxNitrousAddr = ResolvePointer(gameBase, maxNitrousPointer);
        if (maxNitrousAddr != 0 && !IsBadReadPtr(reinterpret_cast<void*>(maxNitrousAddr), sizeof(int))) {
            maxValues[0] = *reinterpret_cast<int*>(maxNitrousAddr);
        }

        int carSpeed = GetCurrentSpeed(gameBase, now);

        if (carSpeed == -999) {
            Sleep(updateIntervalMs);
            continue;
        }

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

        int baseMax = maxValues[0];
        int refillIncrement = static_cast<int>(baseMax / (refillTime * 40));

        uintptr_t addr = ResolvePointer(gameBase, nitrousChain);
        if (addr != 0 && !IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(int))) {
            if (!IsGamePaused(gameBase) && ((now - unpauseTime) >= unpauseBufferMs)) {
                int currentValue = *reinterpret_cast<int*>(addr);
                if (currentValue >= 0 && currentValue <= 99999) {
                    int& lastValue = lastValues[addr];
                    ULONGLONG& lastDecreaseTime = cooldownTimestamps[addr];

                    if (currentValue < lastValue) {
                        lastDecreaseTime = gameTime;
                    }

                    lastValue = currentValue;

                    if ((gameTime - lastDecreaseTime) >= cooldownMs && currentValue < baseMax) {
                        *reinterpret_cast<int*>(addr) = std::min(currentValue + refillIncrement, baseMax);
                    }
                }
            }
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