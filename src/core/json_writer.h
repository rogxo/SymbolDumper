#pragma once

#include "core/types.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace sd {

using json = nlohmann::json;

inline std::string to_hex(uint64_t val) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << val;
    return ss.str();
}

// Write modules.json
inline bool write_modules_json(const std::string& path, const ProcessInfo& proc) {
    json j;
    j["process_id"]   = proc.pid;
    j["process_name"] = proc.name;

    json modules_arr = json::array();
    for (auto& m : proc.modules) {
        json mj;
        mj["name"]         = m.name;
        mj["path"]         = m.path;
        mj["base_address"] = to_hex(m.base_address);
        mj["size"]         = m.size;
        modules_arr.push_back(std::move(mj));
    }
    j["modules"] = std::move(modules_arr);

    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << j.dump(2);
    return f.good();
}

// Write symbols.json
inline bool write_symbols_json(const std::string& path,
                                const ProcessInfo& proc,
                                const std::vector<ModuleSymbols>& all_symbols) {
    json j;
    j["process_id"]   = proc.pid;
    j["process_name"] = proc.name;

    json modules_arr = json::array();
    for (auto& ms : all_symbols) {
        json mj;
        mj["module_name"]  = ms.module.name;
        mj["module_path"]  = ms.module.path;
        mj["base_address"] = to_hex(ms.module.base_address);
        mj["format"]       = "";

        json syms_arr = json::array();
        for (auto& s : ms.symbols) {
            json sj;
            sj["name"]    = s.name;
            sj["rva"]     = to_hex(s.rva);
            sj["address"] = to_hex(s.address);
            sj["type"]    = s.type;
            sj["source"]  = s.source;

            if (!s.library.empty())
                sj["library"] = s.library;
            if (s.ordinal >= 0)
                sj["ordinal"] = s.ordinal;
            if (s.sym_size > 0)
                sj["size"] = s.sym_size;

            syms_arr.push_back(std::move(sj));
        }
        mj["symbol_count"] = ms.symbols.size();
        mj["symbols"]      = std::move(syms_arr);

        modules_arr.push_back(std::move(mj));
    }
    j["modules"] = std::move(modules_arr);

    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << j.dump(2);
    return f.good();
}

} // namespace sd
