#pragma once

#include "core/types.h"
#include "parser/pe_parser.h"
#include "parser/elf_parser.h"
#include "parser/macho_parser.h"
#include <string>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

namespace sd {

enum class BinaryFormat {
    Unknown,
    PE,
    ELF,
    MachO
};

inline BinaryFormat detect_format(const FileData& file) {
    if (file.size() < 4) return BinaryFormat::Unknown;

    uint32_t magic = file.read<uint32_t>(0);
    uint16_t mz    = file.read<uint16_t>(0);

    // PE: starts with 'MZ'
    if (mz == 0x5A4D) return BinaryFormat::PE;

    // ELF: starts with 0x7f 'E' 'L' 'F'
    if (file.size() >= 4 && memcmp(file.raw(), "\x7f""ELF", 4) == 0)
        return BinaryFormat::ELF;

    // Mach-O: various magic values
    if (magic == MH_MAGIC || magic == MH_MAGIC_64 ||
        magic == MH_CIGAM || magic == MH_CIGAM_64 ||
        magic == FAT_MAGIC || magic == FAT_CIGAM)
        return BinaryFormat::MachO;

    return BinaryFormat::Unknown;
}

inline std::string format_name(BinaryFormat fmt) {
    switch (fmt) {
        case BinaryFormat::PE:    return "PE";
        case BinaryFormat::ELF:   return "ELF";
        case BinaryFormat::MachO: return "Mach-O";
        default:                  return "Unknown";
    }
}

// Source priority: higher = preferred when deduplicating
inline int source_priority(const std::string& source) {
    if (source == "export_table")   return 100;
    if (source == "export_trie")    return 95;
    if (source == "import_table")   return 90;
    if (source.find("import(") == 0) return 85;
    if (source == "dynsym")         return 80;
    if (source == "symtab")         return 70;
    if (source == "pdb")            return 60;
    return 50;
}

// Deduplicate symbols: same (name, rva) keeps the higher-priority source.
// Also removes empty-name symbols and merges info where possible.
inline std::vector<SymbolInfo> deduplicate_symbols(const std::vector<SymbolInfo>& symbols) {
    // Key = "name|rva"
    struct SymKey {
        std::string name;
        uint64_t    rva;
        bool operator==(const SymKey& o) const { return name == o.name && rva == o.rva; }
    };
    struct SymKeyHash {
        size_t operator()(const SymKey& k) const {
            size_t h1 = std::hash<std::string>{}(k.name);
            size_t h2 = std::hash<uint64_t>{}(k.rva);
            return h1 ^ (h2 << 1);
        }
    };

    std::unordered_map<SymKey, size_t, SymKeyHash> best; // key -> index in result
    std::vector<SymbolInfo> result;

    for (const auto& sym : symbols) {
        if (sym.name.empty()) continue;

        SymKey key{sym.name, sym.rva};
        auto it = best.find(key);
        if (it == best.end()) {
            best[key] = result.size();
            result.push_back(sym);
        } else {
            // Keep the one with higher source priority
            auto& existing = result[it->second];
            if (source_priority(sym.source) > source_priority(existing.source)) {
                std::string saved_lib = existing.library;
                uint64_t saved_size = existing.sym_size;
                existing = sym;
                // Preserve library info if the new one doesn't have it
                if (existing.library.empty() && !saved_lib.empty())
                    existing.library = saved_lib;
                if (existing.sym_size == 0 && saved_size > 0)
                    existing.sym_size = saved_size;
            } else {
                // Merge useful fields from duplicate into existing
                if (existing.library.empty() && !sym.library.empty())
                    existing.library = sym.library;
                if (existing.sym_size == 0 && sym.sym_size > 0)
                    existing.sym_size = sym.sym_size;
            }
        }
    }

    return result;
}

// Unified parsing: detects format and extracts symbols
struct ParseResult {
    BinaryFormat              format = BinaryFormat::Unknown;
    std::vector<SymbolInfo>   symbols;
    std::vector<std::string>  imported_libs;
    std::string               pdb_path;
    uint64_t                  image_base = 0; // Preferred/default base address from binary
    bool                      is64 = false;
    bool                      success = false;
};

inline ParseResult parse_binary(const std::string& filepath) {
    ParseResult result;

    FileData file;
    if (!file.load(filepath)) return result;

    result.format = detect_format(file);

    switch (result.format) {
    case BinaryFormat::PE: {
        PeParser parser;
        if (parser.parse(file)) {
            result.symbols    = deduplicate_symbols(parser.symbols());
            result.pdb_path   = parser.pdb_path();
            result.image_base = parser.image_base();
            result.is64       = parser.is64bit();
            result.success    = true;
        }
        break;
    }
    case BinaryFormat::ELF: {
        ElfParser parser;
        if (parser.parse(file)) {
            result.symbols       = deduplicate_symbols(parser.symbols());
            result.imported_libs = parser.needed_libs();
            result.image_base    = parser.image_base();
            result.is64          = parser.is64bit();
            result.success       = true;
        }
        break;
    }
    case BinaryFormat::MachO: {
        MachOParser parser;
        if (parser.parse(file)) {
            result.symbols       = deduplicate_symbols(parser.symbols());
            result.imported_libs = parser.imported_libs();
            result.image_base    = parser.image_base();
            result.is64          = parser.is64bit();
            result.success       = true;
        }
        break;
    }
    default:
        break;
    }

    return result;
}

} // namespace sd
