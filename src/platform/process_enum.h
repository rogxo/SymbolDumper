#pragma once

#include "core/types.h"
#include <string>
#include <vector>

namespace sd {

// Cross-platform process module enumeration interface
// Each platform implements enumerate_modules()

// Enumerate all modules loaded in a target process
bool enumerate_modules(uint32_t pid, ProcessInfo& out_info);

// List all running processes (pid + name)
struct ProcessEntry {
    uint32_t    pid;
    std::string name;
};

std::vector<ProcessEntry> list_processes();

} // namespace sd
