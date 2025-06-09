#include "Proxy.hpp"

#include <Windows.h>
#include <iostream>
#include <thread>
#include <dbghelp.h>
#include <filesystem>
#include <map>

#include "MinHook.h"

bool InitializeSymbols() {
    SymSetOptions(SYMOPT_UNDNAME);
    if (!SymInitialize(reinterpret_cast<HANDLE>(-1), nullptr, TRUE)) {
        printf("Failed to initialize debug help\n");
        return false;
    }

    const auto factorioModule = GetModuleHandleA(nullptr);
    char executablePath[MAX_PATH];
    GetModuleFileNameA(factorioModule, executablePath, MAX_PATH);
    printf("Factorio executable is at: %s\n", executablePath);

    const auto executablePathFs = std::filesystem::path(executablePath).parent_path();
    const auto pdbPath = executablePathFs / "factorio.pdb";
    if (!exists(pdbPath)) {
        printf("PDB isn't present, please wube software don't do this.\n");
        return false;
    }

    printf("Factorio PDB is at: %s\n", pdbPath.string().c_str());
    if (!SymUnloadModule64(reinterpret_cast<HANDLE>(-1), reinterpret_cast<DWORD64>(factorioModule))) {
        printf("Failed to unload faulty module info, how?\n");
        return false;
    }

    if (SymLoadModuleEx(reinterpret_cast<HANDLE>(-1), nullptr, pdbPath.string().c_str(), nullptr,
                        reinterpret_cast<DWORD64>(factorioModule), std::filesystem::file_size(pdbPath), nullptr,
                        0) == 0) {
        printf("Failed to load PDB, please complain to windows gods\n");
        return false;
    }

    printf("Loaded PDB for factorio!\n");
    return true;
}

std::map<std::string, DWORD> GetStructClassMembers(const char *symbolName) {
    std::map<std::string, DWORD> foundMembers;
    const auto moduleBase = reinterpret_cast<DWORD64>(GetModuleHandleA(nullptr));

    struct SearchContext {
        const char *searchName;
        DWORD typeIndex;
        DWORD64 modBase;
        bool found;
    };
    auto context = SearchContext{};

    SymEnumTypesByName(reinterpret_cast<HANDLE>(-1), moduleBase, symbolName,
                       [](PSYMBOL_INFO symInfo, ULONG symbolSize, PVOID UserContext) -> BOOL {
                           auto ctx = static_cast<SearchContext *>(UserContext);

                           if (symInfo->Tag == SymTagUDT) {
                               ctx->typeIndex = symInfo->TypeIndex;
                               ctx->modBase = symInfo->ModBase;
                               ctx->found = true;
                               return FALSE;
                           }
                           return TRUE;
                       }, &context);

    if (!context.found) {
        printf("Couldn't find struct/class %s to enumerate it's members!\n", symbolName);
        return foundMembers;
    }

    ULONG64 symbolSize = 0;
    if (!SymGetTypeInfo(reinterpret_cast<HANDLE>(-1), context.modBase, context.typeIndex, TI_GET_LENGTH, &symbolSize)) {
        printf("Failed to get symbol size for %s\n", symbolName);
        return foundMembers;
    }

    DWORD memberCount = 0;
    if (!SymGetTypeInfo(reinterpret_cast<HANDLE>(-1), context.modBase, context.typeIndex, TI_GET_CHILDRENCOUNT,
                        &memberCount)) {
        printf("Failed to get symbol member count for %s\n", symbolName);
        return foundMembers;
    }

    if (memberCount > 0) {
        const DWORD bufferSize = sizeof(TI_FINDCHILDREN_PARAMS) + (memberCount - 1) * sizeof(ULONG);
        auto *Children = static_cast<TI_FINDCHILDREN_PARAMS *>(malloc(bufferSize));

        Children->Count = memberCount;
        Children->Start = 0;
        if (SymGetTypeInfo(reinterpret_cast<HANDLE>(-1), context.modBase, context.typeIndex, TI_FINDCHILDREN,
                           Children)) {
            for (DWORD i = 0; i < memberCount; i++) {
                DWORD childIndex = Children->ChildId[i];
                DWORD childTag = 0;
                SymGetTypeInfo(reinterpret_cast<HANDLE>(-1), context.modBase, childIndex, TI_GET_SYMTAG, &childTag);

                if (childTag == SymTagData) {
                    WCHAR *memberName = nullptr;
                    if (SymGetTypeInfo(reinterpret_cast<HANDLE>(-1), context.modBase, childIndex, TI_GET_SYMNAME,
                                       &memberName)) {
                        DWORD offset = 0;
                        SymGetTypeInfo(reinterpret_cast<HANDLE>(-1), context.modBase, childIndex, TI_GET_OFFSET,
                                       &offset);

                        char nameBuffer[256];
                        WideCharToMultiByte(CP_ACP, 0, memberName, -1, nameBuffer, sizeof(nameBuffer), nullptr,
                                            nullptr);

                        foundMembers[nameBuffer] = offset;
                        LocalFree(memberName);
                    }
                }
            }
        }

        free(Children);
    }

    return foundMembers;
}

typedef uint8_t (__fastcall *AchievementStats__allowed__t)(uintptr_t mapPointer, uintptr_t a, uintptr_t b, uintptr_t c);

static AchievementStats__allowed__t originalIsAllowed = nullptr;
static DWORD associatedContextOffset = 0;

uint8_t __fastcall AchievementStats__allowed__Hook(uintptr_t mapPointer, uintptr_t a, uintptr_t b, uintptr_t c) {
    /**
     * To allow mods be counted towards achievement, we need to trick the code into thinking there are no mods.
     * But we still need to preserve the checks that disallow such if cheats have been used.
     * Can be achieved by nulling out the associatedContext pointer which is the one it needs for mods, if it's nullptr it will move on.
     *
     * Once function is done, we capture it's result and restore associatedContext.
     */
    const auto originalAssociatedContext = *reinterpret_cast<uintptr_t *>(mapPointer + associatedContextOffset);
    *reinterpret_cast<uintptr_t *>(mapPointer + associatedContextOffset) = 0;

    const auto functionResult = originalIsAllowed(mapPointer, a, b, c);

    *reinterpret_cast<uintptr_t *>(mapPointer + associatedContextOffset) = originalAssociatedContext;
    return functionResult;
}

void entry() {
    FILE *stream;
    if (!AttachConsole(-1))
        AllocConsole();
    freopen_s(&stream, "CONOUT$", "w+", stdout);

    if (!InitializeSymbols()) {
        return;
    }
    if (MH_Initialize() != MH_OK) {
        printf("Failed to initialize minhook\n");
        return;
    }

    SYMBOL_INFO_PACKAGE isAllowedSymbolInfo = {0};
    isAllowedSymbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    isAllowedSymbolInfo.si.MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(reinterpret_cast<HANDLE>(-1), "AchievementStats::allowed", &isAllowedSymbolInfo.si)) {
        printf("Failed to find AchievementStats::allowed\n");
        return;
    }

    const auto mapMembers = GetStructClassMembers("Map");
    if (!mapMembers.contains("associatedContext")) {
        printf("Failed to find associatedContext offset in Map!\n");
        return;
    }
    associatedContextOffset = mapMembers.at("associatedContext");

    MH_CreateHook(reinterpret_cast<LPVOID>(isAllowedSymbolInfo.si.Address), AchievementStats__allowed__Hook,
                  static_cast<LPVOID *>(static_cast<void *>(&originalIsAllowed)));
    MH_EnableHook(reinterpret_cast<LPVOID>(isAllowedSymbolInfo.si.Address));
    printf("Hooked AchievementStats::allowed\n");

    SYMBOL_INFO_PACKAGE globalContextSingletonSymbolInfo = {0};
    globalContextSingletonSymbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    globalContextSingletonSymbolInfo.si.MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(reinterpret_cast<HANDLE>(-1), "global", &globalContextSingletonSymbolInfo.si)) {
        printf("Failed to find global singleton\n");
        return;
    }

    const auto globalContextMembers = GetStructClassMembers("GlobalContext");
    if (!globalContextMembers.contains("playerData") || !globalContextMembers.contains("modManager")) {
        printf("Failed to find playerData or modManager offset in global context!");
        return;
    }
    const auto playerDataOffset = globalContextMembers.at("playerData");
    const auto modManagerOffset = globalContextMembers.at("modManager");

    const auto playerDataMembers = GetStructClassMembers("PlayerData");
    if (!playerDataMembers.contains("achievementsAreModded")) {
        printf("Failed to find achievementsAreModded in PlayerData\n");
        return;
    }
    const auto achievementsAreModdedOffset = playerDataMembers.at("achievementsAreModded");

    const auto modManagerMembers = GetStructClassMembers("ModManager");
    if (!modManagerMembers.contains("rawMods")) {
        printf("Failed to find rawMods in ModManager\n");
        return;
    }
    const auto rawModsOffset = modManagerMembers.at("rawMods");

    const auto modMembers = GetStructClassMembers("Mod");
    if (!modMembers.contains("defaultMod") || !modMembers.contains("id")) {
        printf("Failed to find defaultMod or id in Mod\n");
        return;
    }
    const auto isDefaultOffset = modMembers.at("defaultMod");
    const auto modIdOffset = modMembers.at("id");

    auto globalContext = *reinterpret_cast<uintptr_t *>(globalContextSingletonSymbolInfo.si.Address);
    if (globalContext == 0) {
        while (globalContext == 0) {
            globalContext = *reinterpret_cast<uintptr_t *>(globalContextSingletonSymbolInfo.si.Address);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    printf("Global Context: 0x%llX\n", globalContext);
    auto playerData = *reinterpret_cast<uintptr_t *>(globalContext + playerDataOffset);
    if (playerData == 0) {
        while (playerData == 0) {
            playerData = *reinterpret_cast<uintptr_t *>(globalContext + playerDataOffset);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    printf("Player Data: 0x%llX\n", playerData);
    const auto achievementsAreModded = *reinterpret_cast<uint8_t *>(playerData + achievementsAreModdedOffset);
    printf("achievementsAreModded: %d\n", achievementsAreModded);
    if (achievementsAreModded == 1) {
        *reinterpret_cast<uint8_t *>(playerData + achievementsAreModdedOffset) = 0;
        printf("achievementsAreModded was true, we have set it to false!\n");
    }

    const auto modManager = *reinterpret_cast<uintptr_t *>(globalContext + modManagerOffset);
    const auto rawMods = *reinterpret_cast<std::vector<uintptr_t> *>(modManager + rawModsOffset);
    for (const auto modAddress: rawMods) {
        const auto isDefaultMod = *reinterpret_cast<uint8_t *>(modAddress + isDefaultOffset);
        const auto modId = *reinterpret_cast<std::string *>(modAddress + modIdOffset);
        if (isDefaultMod == 0) {
            *reinterpret_cast<uint8_t *>(modAddress + isDefaultOffset) = 1;
            printf("Mod at 0x%llx with id %s isn't default mod, we have set it to default.\n", modAddress,
                   modId.c_str());
        }
    }

    printf("Successfully enabled achievements for modded gameplay, this console is going to close in 10 seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(10));
    const auto consoleWindow = GetConsoleWindow();
    FreeConsole();
    SendMessage(consoleWindow, WM_CLOSE, 0, 0);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            std::thread(entry).detach();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            if (lpvReserved != nullptr) {
                break;
            }
            break;
        default:
            break;
    }
    return TRUE;
}
