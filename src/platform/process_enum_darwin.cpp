#include "platform/process_enum.h"

#ifdef SD_PLATFORM_DARWIN

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <array>
#include <set>

// macOS/iOS specific headers
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

namespace sd {

static std::string get_proc_name(pid_t pid) {
    char name[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (proc_name(pid, name, sizeof(name)) > 0) {
        return name;
    }
    return "";
}

static std::string get_proc_path(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (proc_pidpath(pid, path, sizeof(path)) > 0) {
        return path;
    }
    return "";
}

bool enumerate_modules(uint32_t pid, ProcessInfo& out_info) {
    out_info.pid = pid;
    out_info.modules.clear();
    out_info.name = get_proc_name(static_cast<pid_t>(pid));

    // Use task_for_pid to get the task port (requires root or entitlements)
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), static_cast<pid_t>(pid), &task);
    if (kr != KERN_SUCCESS) {
        // Fallback: try to get module info from dyld info via proc_regionfilename
        // This works without task_for_pid on macOS for some cases
        mach_vm_address_t address = 0;
        mach_vm_size_t size = 0;

        // Use proc_regionfilename to enumerate mapped files
        struct proc_regionwithpathinfo rwpi;
        std::set<std::string> seen_paths;

        // Scan address space using proc_pidinfo
        // This is limited but works without special permissions
        uint64_t scan_addr = 0;
        while (scan_addr < 0x7FFFFFFFFFFF) {
            char path[PROC_PIDPATHINFO_MAXSIZE] = {};
            int ret = proc_regionfilename(pid, scan_addr, path, sizeof(path));
            if (ret <= 0) {
                scan_addr += 0x1000; // Page size increment
                if (scan_addr > 0x7FFFFFFFFFFF) break;
                continue;
            }

            std::string filepath(path);
            if (!filepath.empty() && seen_paths.find(filepath) == seen_paths.end()) {
                seen_paths.insert(filepath);

                ModuleInfo mi;
                mi.path = filepath;
                mi.base_address = scan_addr;

                auto slash = mi.path.find_last_of('/');
                mi.name = (slash != std::string::npos) ? mi.path.substr(slash + 1) : mi.path;

                out_info.modules.push_back(std::move(mi));
            }

            scan_addr += 0x1000;
        }

        return !out_info.modules.empty();
    }

    // With task port: enumerate regions using mach_vm_region
    mach_vm_address_t address = 0;
    std::set<std::string> seen_paths;

    while (true) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name;

        kr = mach_vm_region(task, &address, &size,
                           VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &info_count,
                           &object_name);
        if (kr != KERN_SUCCESS) break;

        // Get the file path for this region
        char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        int ret = proc_regionfilename(pid, address, path, sizeof(path));

        if (ret > 0) {
            std::string filepath(path);
            if (!filepath.empty() && seen_paths.find(filepath) == seen_paths.end()) {
                seen_paths.insert(filepath);

                ModuleInfo mi;
                mi.path = filepath;
                mi.base_address = address;
                mi.size = size;

                auto slash = mi.path.find_last_of('/');
                mi.name = (slash != std::string::npos) ? mi.path.substr(slash + 1) : mi.path;

                // Find total size by scanning subsequent regions with same path
                mach_vm_address_t scan = address + size;
                while (true) {
                    mach_vm_size_t scan_size = 0;
                    vm_region_basic_info_data_64_t scan_info;
                    mach_msg_type_number_t scan_count = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t scan_obj;

                    if (mach_vm_region(task, &scan, &scan_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&scan_info, &scan_count,
                                      &scan_obj) != KERN_SUCCESS) break;

                    char scan_path[PROC_PIDPATHINFO_MAXSIZE] = {};
                    if (proc_regionfilename(pid, scan, scan_path, sizeof(scan_path)) > 0 &&
                        filepath == scan_path) {
                        mi.size = (scan + scan_size) - address;
                        scan += scan_size;
                    } else {
                        break;
                    }
                }

                out_info.modules.push_back(std::move(mi));
            }
        }

        address += size;
    }

    mach_port_deallocate(mach_task_self(), task);
    return !out_info.modules.empty();
}

std::vector<ProcessEntry> list_processes() {
    std::vector<ProcessEntry> result;

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;

    if (sysctl(mib, 4, nullptr, &size, nullptr, 0) < 0) return result;

    std::vector<struct kinfo_proc> procs(size / sizeof(struct kinfo_proc));
    if (sysctl(mib, 4, procs.data(), &size, nullptr, 0) < 0) return result;

    size_t count = size / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < count; ++i) {
        ProcessEntry pe;
        pe.pid  = static_cast<uint32_t>(procs[i].kp_proc.p_pid);
        pe.name = procs[i].kp_proc.p_comm;
        if (!pe.name.empty()) {
            result.push_back(std::move(pe));
        }
    }

    return result;
}

} // namespace sd

#endif // SD_PLATFORM_DARWIN
