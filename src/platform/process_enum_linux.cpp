#include "platform/process_enum.h"

#ifdef SD_PLATFORM_LINUX

#include <fstream>
#include <sstream>
#include <dirent.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <algorithm>
#include <set>

namespace sd {

static std::string read_proc_name(uint32_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream f(path);
    std::string name;
    if (f.is_open() && std::getline(f, name)) {
        // Remove trailing newline
        while (!name.empty() && (name.back() == '\n' || name.back() == '\r'))
            name.pop_back();
        return name;
    }
    return "";
}

bool enumerate_modules(uint32_t pid, ProcessInfo& out_info) {
    out_info.pid = pid;
    out_info.modules.clear();
    out_info.name = read_proc_name(pid);

    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream f(maps_path);
    if (!f.is_open()) return false;

    // Parse /proc/<pid>/maps
    // Format: address perms offset dev inode pathname
    // Example: 7f1234560000-7f1234580000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6

    struct MappedRegion {
        uint64_t    start;
        uint64_t    end;
        std::string path;
        bool        executable;
    };

    std::vector<MappedRegion> regions;
    std::string line;

    while (std::getline(f, line)) {
        MappedRegion region{};

        // Parse address range
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;
        region.start = strtoull(line.c_str(), nullptr, 16);
        region.end   = strtoull(line.c_str() + dash + 1, nullptr, 16);

        // Parse permissions
        size_t space1 = line.find(' ', dash);
        if (space1 == std::string::npos) continue;
        std::string perms = line.substr(space1 + 1, 4);
        region.executable = (perms.find('x') != std::string::npos);

        // Find pathname (skip offset, dev, inode)
        // Count spaces: after perms, offset, dev, inode, then pathname
        size_t pos = space1 + 1;
        for (int skip = 0; skip < 4 && pos < line.size(); ++skip) {
            pos = line.find(' ', pos);
            if (pos == std::string::npos) break;
            pos++;
        }

        if (pos < line.size()) {
            // Skip leading whitespace
            while (pos < line.size() && line[pos] == ' ') pos++;
            if (pos < line.size() && line[pos] == '/') {
                region.path = line.substr(pos);
                // Remove trailing whitespace
                while (!region.path.empty() && (region.path.back() == ' ' ||
                       region.path.back() == '\n' || region.path.back() == '\r'))
                    region.path.pop_back();
            }
        }

        if (!region.path.empty()) {
            regions.push_back(std::move(region));
        }
    }

    // Group regions by path to create modules
    // A module is identified by its file path
    // The base address is the lowest address, size is highest - lowest
    std::set<std::string> seen_paths;

    for (auto& r : regions) {
        if (r.path.empty()) continue;
        if (r.path[0] != '/') continue;  // Skip [vdso], [stack], etc.
        if (seen_paths.count(r.path)) continue;
        seen_paths.insert(r.path);

        // Find the full extent of this mapping
        uint64_t base = r.start;
        uint64_t end  = r.end;
        for (auto& r2 : regions) {
            if (r2.path == r.path) {
                if (r2.start < base) base = r2.start;
                if (r2.end > end) end = r2.end;
            }
        }

        ModuleInfo mi;
        mi.path = r.path;
        mi.base_address = base;
        mi.size = end - base;

        // Extract filename
        auto slash = mi.path.find_last_of('/');
        mi.name = (slash != std::string::npos) ? mi.path.substr(slash + 1) : mi.path;

        out_info.modules.push_back(std::move(mi));
    }

    return !out_info.modules.empty();
}

std::vector<ProcessEntry> list_processes() {
    std::vector<ProcessEntry> result;

    DIR* dir = opendir("/proc");
    if (!dir) return result;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Check if the directory name is a number (PID)
        bool is_pid = true;
        for (const char* p = entry->d_name; *p; ++p) {
            if (*p < '0' || *p > '9') { is_pid = false; break; }
        }
        if (!is_pid || entry->d_name[0] == '\0') continue;

        ProcessEntry pe;
        pe.pid  = static_cast<uint32_t>(atoi(entry->d_name));
        pe.name = read_proc_name(pe.pid);

        if (!pe.name.empty()) {
            result.push_back(std::move(pe));
        }
    }

    closedir(dir);
    return result;
}

} // namespace sd

#endif // SD_PLATFORM_LINUX
