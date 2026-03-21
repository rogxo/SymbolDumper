#include "platform/process_enum.h"

#ifdef SD_PLATFORM_WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>

namespace sd {

static std::string wstr_to_utf8(const wchar_t* wstr) {
    if (!wstr || !wstr[0]) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}

bool enumerate_modules(uint32_t pid, ProcessInfo& out_info) {
    out_info.pid = pid;
    out_info.modules.clear();

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, static_cast<DWORD>(pid));
    if (!hProcess) return false;

    // Get process name
    wchar_t proc_name[MAX_PATH] = {};
    if (GetModuleBaseNameW(hProcess, nullptr, proc_name, MAX_PATH)) {
        out_info.name = wstr_to_utf8(proc_name);
    }

    // Enumerate modules
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            ModuleInfo mi;
            mi.base_address = reinterpret_cast<uint64_t>(hMods[i]);

            wchar_t modName[MAX_PATH] = {};
            if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
                mi.path = wstr_to_utf8(modName);
                // Extract just the filename
                auto pos = mi.path.find_last_of("\\/");
                mi.name = (pos != std::string::npos) ? mi.path.substr(pos + 1) : mi.path;
            }

            MODULEINFO modInfo = {};
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                mi.size = modInfo.SizeOfImage;
            }

            out_info.modules.push_back(std::move(mi));
        }
    }

    CloseHandle(hProcess);
    return !out_info.modules.empty();
}

std::vector<ProcessEntry> list_processes() {
    std::vector<ProcessEntry> result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            ProcessEntry entry;
            entry.pid  = pe.th32ProcessID;
            entry.name = wstr_to_utf8(pe.szExeFile);
            result.push_back(std::move(entry));
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

} // namespace sd

#endif // SD_PLATFORM_WINDOWS
