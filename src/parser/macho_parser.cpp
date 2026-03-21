#include "parser/macho_parser.h"
#include <algorithm>
#include <cstring>

namespace sd {

static uint32_t swap32(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}

static uint64_t read_uleb128(const uint8_t* p, const uint8_t* end, size_t& bytes_read) {
    uint64_t result = 0;
    unsigned shift = 0;
    bytes_read = 0;
    while (p < end) {
        uint8_t byte = *p++;
        bytes_read++;
        result |= (uint64_t)(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

bool MachOParser::parse(const FileData& file) {
    symbols_.clear();
    imported_libs_.clear();

    if (file.size() < 4) return false;

    uint32_t magic = file.read<uint32_t>(0);

    // Handle fat/universal binaries - pick the first architecture
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        bool fat_swap = (magic == FAT_CIGAM);
        auto fh = file.at<FatHeader>(0);
        if (!fh) return false;
        uint32_t narch = fat_swap ? swap32(fh->nfat_arch) : fh->nfat_arch;
        if (narch == 0) return false;

        // Parse the first arch (could be extended to let user choose)
        auto fa = file.at<FatArch>(sizeof(FatHeader));
        if (!fa) return false;
        uint32_t offset = fat_swap ? swap32(fa->offset) : fa->offset;
        return parse_single(file, offset);
    }

    return parse_single(file, 0);
}

bool MachOParser::parse_single(const FileData& file, size_t base_offset) {
    if (base_offset + 4 > file.size()) return false;

    uint32_t magic = file.read<uint32_t>(base_offset);
    swap_ = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    is64_ = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);

    if (magic != MH_MAGIC && magic != MH_MAGIC_64 &&
        magic != MH_CIGAM && magic != MH_CIGAM_64) {
        return false;
    }

    uint32_t ncmds, sizeofcmds;
    size_t header_size;

    if (is64_) {
        auto hdr = file.at<MachO_Header64>(base_offset);
        if (!hdr) return false;
        ncmds = swap_ ? swap32(hdr->ncmds) : hdr->ncmds;
        sizeofcmds = swap_ ? swap32(hdr->sizeofcmds) : hdr->sizeofcmds;
        header_size = sizeof(MachO_Header64);
    } else {
        auto hdr = file.at<MachO_Header>(base_offset);
        if (!hdr) return false;
        ncmds = swap_ ? swap32(hdr->ncmds) : hdr->ncmds;
        sizeofcmds = swap_ ? swap32(hdr->sizeofcmds) : hdr->sizeofcmds;
        header_size = sizeof(MachO_Header);
    }

    size_t cmd_offset = base_offset + header_size;
    size_t cmd_end = cmd_offset + sizeofcmds;

    MachO_SymtabCommand symtab_cmd{};
    MachO_DysymtabCommand dysymtab_cmd{};
    bool has_symtab = false, has_dysymtab = false;
    MachO_DyldInfoCommand dyld_info_cmd{};
    bool has_dyld_info = false;
    uint32_t export_trie_off = 0, export_trie_size = 0;

    for (uint32_t i = 0; i < ncmds && cmd_offset < cmd_end; ++i) {
        auto lc = file.at<MachO_LoadCommand>(cmd_offset);
        if (!lc) break;

        uint32_t cmd = swap_ ? swap32(lc->cmd) : lc->cmd;
        uint32_t cmdsize = swap_ ? swap32(lc->cmdsize) : lc->cmdsize;
        if (cmdsize < sizeof(MachO_LoadCommand)) break;

        switch (cmd) {
        case LC_SYMTAB: {
            auto sc = file.at<MachO_SymtabCommand>(cmd_offset);
            if (sc) {
                symtab_cmd = *sc;
                if (swap_) {
                    symtab_cmd.symoff  = swap32(symtab_cmd.symoff);
                    symtab_cmd.nsyms   = swap32(symtab_cmd.nsyms);
                    symtab_cmd.stroff  = swap32(symtab_cmd.stroff);
                    symtab_cmd.strsize = swap32(symtab_cmd.strsize);
                }
                has_symtab = true;
            }
            break;
        }
        case LC_DYSYMTAB: {
            auto dc = file.at<MachO_DysymtabCommand>(cmd_offset);
            if (dc) {
                dysymtab_cmd = *dc;
                if (swap_) {
                    dysymtab_cmd.ilocalsym  = swap32(dysymtab_cmd.ilocalsym);
                    dysymtab_cmd.nlocalsym  = swap32(dysymtab_cmd.nlocalsym);
                    dysymtab_cmd.iextdefsym = swap32(dysymtab_cmd.iextdefsym);
                    dysymtab_cmd.nextdefsym = swap32(dysymtab_cmd.nextdefsym);
                    dysymtab_cmd.iundefsym  = swap32(dysymtab_cmd.iundefsym);
                    dysymtab_cmd.nundefsym  = swap32(dysymtab_cmd.nundefsym);
                    dysymtab_cmd.nindirectsyms = swap32(dysymtab_cmd.nindirectsyms);
                    dysymtab_cmd.indirectsymoff = swap32(dysymtab_cmd.indirectsymoff);
                }
                has_dysymtab = true;
            }
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB: {
            auto dc = file.at<MachO_DylibCommand>(cmd_offset);
            if (dc) {
                uint32_t name_off = swap_ ? swap32(dc->name_offset) : dc->name_offset;
                std::string lib = file.read_string(cmd_offset + name_off);
                if (!lib.empty()) imported_libs_.push_back(lib);
            }
            break;
        }
        case LC_SEGMENT: {
            auto seg = file.at<MachO_SegmentCommand>(cmd_offset);
            if (seg && strncmp(seg->segname, "__TEXT", 6) == 0) {
                image_base_ = swap_ ? swap32(seg->vmaddr) : seg->vmaddr;
            }
            break;
        }
        case LC_SEGMENT_64: {
            auto seg = file.at<MachO_SegmentCommand64>(cmd_offset);
            if (seg && strncmp(seg->segname, "__TEXT", 6) == 0) {
                uint64_t vmaddr = seg->vmaddr;
                if (swap_) {
                    vmaddr = ((uint64_t)swap32((uint32_t)(vmaddr >> 32))) |
                             ((uint64_t)swap32((uint32_t)vmaddr) << 32);
                }
                image_base_ = vmaddr;
            }
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            auto di = file.at<MachO_DyldInfoCommand>(cmd_offset);
            if (di) {
                dyld_info_cmd = *di;
                if (swap_) {
                    dyld_info_cmd.bind_off       = swap32(dyld_info_cmd.bind_off);
                    dyld_info_cmd.bind_size      = swap32(dyld_info_cmd.bind_size);
                    dyld_info_cmd.weak_bind_off  = swap32(dyld_info_cmd.weak_bind_off);
                    dyld_info_cmd.weak_bind_size = swap32(dyld_info_cmd.weak_bind_size);
                    dyld_info_cmd.lazy_bind_off  = swap32(dyld_info_cmd.lazy_bind_off);
                    dyld_info_cmd.lazy_bind_size = swap32(dyld_info_cmd.lazy_bind_size);
                    dyld_info_cmd.export_off     = swap32(dyld_info_cmd.export_off);
                    dyld_info_cmd.export_size    = swap32(dyld_info_cmd.export_size);
                }
                has_dyld_info = true;
            }
            break;
        }
        case LC_DYLD_EXPORTS_TRIE: {
            auto ld = file.at<MachO_LinkeditDataCommand>(cmd_offset);
            if (ld) {
                export_trie_off  = swap_ ? swap32(ld->dataoff)  : ld->dataoff;
                export_trie_size = swap_ ? swap32(ld->datasize) : ld->datasize;
            }
            break;
        }
        default:
            break;
        }

        cmd_offset += cmdsize;
    }

    // Parse symbol table
    if (has_symtab) {
        symtab_off_   = symtab_cmd.symoff + base_offset;
        symtab_nsyms_ = symtab_cmd.nsyms;
        strtab_off_   = symtab_cmd.stroff + base_offset;
        strtab_size_  = symtab_cmd.strsize;
        parse_symtab(file, base_offset, symtab_cmd);
    }

    // Parse dysymtab (uses symtab data for cross-reference)
    if (has_dysymtab && has_symtab) {
        parse_dysymtab(file, base_offset, dysymtab_cmd);
    }

    // Parse export trie
    if (has_dyld_info && dyld_info_cmd.export_size > 0) {
        parse_export_trie(file, dyld_info_cmd.export_off + base_offset,
                          dyld_info_cmd.export_size);
    } else if (export_trie_off > 0 && export_trie_size > 0) {
        parse_export_trie(file, export_trie_off + base_offset, export_trie_size);
    }

    // Parse bind info (imports)
    if (has_dyld_info) {
        if (dyld_info_cmd.bind_size > 0) {
            parse_bind_info(file, dyld_info_cmd.bind_off + base_offset,
                           dyld_info_cmd.bind_size, "bind");
        }
        if (dyld_info_cmd.lazy_bind_size > 0) {
            parse_bind_info(file, dyld_info_cmd.lazy_bind_off + base_offset,
                           dyld_info_cmd.lazy_bind_size, "lazy_bind");
        }
        if (dyld_info_cmd.weak_bind_size > 0) {
            parse_bind_info(file, dyld_info_cmd.weak_bind_off + base_offset,
                           dyld_info_cmd.weak_bind_size, "weak_bind");
        }
    }

    return true;
}

void MachOParser::parse_symtab(const FileData& file, size_t base_offset,
                                const MachO_SymtabCommand& cmd) {
    size_t sym_off = cmd.symoff + base_offset;
    size_t str_off = cmd.stroff + base_offset;
    uint32_t str_size = cmd.strsize;
    size_t entry_size = is64_ ? sizeof(MachO_Nlist64) : sizeof(MachO_Nlist);

    for (uint32_t i = 0; i < cmd.nsyms; ++i) {
        size_t off = sym_off + i * entry_size;
        uint32_t n_strx;
        uint8_t  n_type, n_sect;
        uint64_t n_value;

        if (is64_) {
            auto nl = file.at<MachO_Nlist64>(off);
            if (!nl) break;
            n_strx  = nl->n_strx;
            n_type  = nl->n_type;
            n_sect  = nl->n_sect;
            n_value = nl->n_value;
        } else {
            auto nl = file.at<MachO_Nlist>(off);
            if (!nl) break;
            n_strx  = nl->n_strx;
            n_type  = nl->n_type;
            n_sect  = nl->n_sect;
            n_value = nl->n_value;
        }

        // Skip debug/stab symbols
        if (n_type & N_STAB) continue;

        if (n_strx == 0 || n_strx >= str_size) continue;
        std::string name = file.read_string(str_off + n_strx);
        if (name.empty()) continue;

        SymbolInfo si;
        si.name = name;
        si.rva  = n_value;

        uint8_t type_field = n_type & N_TYPE;
        if (type_field == N_UNDF) {
            si.source = "import(symtab)";
            si.type   = "function";
        } else if (type_field == N_SECT) {
            si.source = "symtab";
            si.type   = (n_type & N_EXT) ? "function" : "local";
        } else if (type_field == N_ABS) {
            si.source = "symtab";
            si.type   = "absolute";
        } else if (type_field == N_INDR) {
            si.source = "symtab";
            si.type   = "indirect";
        } else {
            si.source = "symtab";
            si.type   = "unknown";
        }

        symbols_.push_back(std::move(si));
    }
}

void MachOParser::parse_dysymtab(const FileData& file, size_t base_offset,
                                  const MachO_DysymtabCommand& cmd) {
    // The dysymtab provides index ranges into the symtab:
    //   [ilocalsym, ilocalsym+nlocalsym)   = local symbols
    //   [iextdefsym, iextdefsym+nextdefsym) = exported symbols
    //   [iundefsym, iundefsym+nundefsym)    = imported (undefined) symbols
    // We already parsed all from symtab, but we can annotate with better source info.
    // For now, the symtab parse already handles this via N_TYPE checking.
    (void)file;
    (void)base_offset;
    (void)cmd;
}

void MachOParser::parse_export_trie(const FileData& file, size_t trie_offset, size_t trie_size) {
    if (trie_offset + trie_size > file.size()) return;
    walk_export_trie(file, trie_offset, trie_size, 0, "");
}

void MachOParser::walk_export_trie(const FileData& file, size_t trie_start, size_t trie_size,
                                    size_t node_offset, const std::string& prefix) {
    if (node_offset >= trie_size) return;

    const uint8_t* start = file.raw(trie_start);
    const uint8_t* end   = start + trie_size;
    const uint8_t* p     = start + node_offset;

    if (!start || p >= end) return;

    // Terminal size
    size_t bytes;
    uint64_t terminal_size = read_uleb128(p, end, bytes);
    p += bytes;

    if (terminal_size != 0) {
        const uint8_t* terminal_start = p;
        uint64_t flags = read_uleb128(p, end, bytes);
        p += bytes;

        SymbolInfo si;
        si.name   = prefix;
        si.source = "export_trie";

        if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
            uint64_t ordinal = read_uleb128(p, end, bytes);
            p += bytes;
            // Read re-exported name
            std::string reexport_name;
            while (p < end && *p != 0) {
                reexport_name.push_back(static_cast<char>(*p++));
            }
            si.type    = "reexport";
            si.library = reexport_name.empty() ? prefix : reexport_name;
            si.ordinal = static_cast<int64_t>(ordinal);
        } else {
            uint64_t sym_offset = read_uleb128(p, end, bytes);
            p += bytes;
            si.rva  = sym_offset;
            si.type = "function";

            if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
                uint64_t resolver_offset = read_uleb128(p, end, bytes);
                p += bytes;
                (void)resolver_offset;
                si.type = "resolver";
            }
        }

        symbols_.push_back(std::move(si));
        p = terminal_start + terminal_size;
    }

    // Children
    if (p >= end) return;
    uint8_t child_count = *p++;

    for (uint8_t i = 0; i < child_count && p < end; ++i) {
        // Read edge label (null-terminated string)
        std::string edge;
        while (p < end && *p != 0) {
            edge.push_back(static_cast<char>(*p++));
        }
        if (p < end) ++p; // skip null terminator

        uint64_t child_node_offset = read_uleb128(p, end, bytes);
        p += bytes;

        walk_export_trie(file, trie_start, trie_size,
                         static_cast<size_t>(child_node_offset),
                         prefix + edge);
    }
}

void MachOParser::parse_bind_info(const FileData& file, size_t bind_offset, size_t bind_size,
                                   const std::string& bind_type) {
    if (bind_offset + bind_size > file.size()) return;

    const uint8_t* p   = file.raw(bind_offset);
    const uint8_t* end = p + bind_size;
    if (!p) return;

    // Bind opcodes
    static constexpr uint8_t BIND_OPCODE_MASK                = 0xF0;
    static constexpr uint8_t BIND_IMMEDIATE_MASK             = 0x0F;
    static constexpr uint8_t BIND_OPCODE_DONE                = 0x00;
    static constexpr uint8_t BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10;
    static constexpr uint8_t BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20;
    static constexpr uint8_t BIND_OPCODE_SET_DYLIB_SPECIAL   = 0x30;
    static constexpr uint8_t BIND_OPCODE_SET_SYMBOL_TRAILING  = 0x40;
    static constexpr uint8_t BIND_OPCODE_SET_TYPE             = 0x50;
    static constexpr uint8_t BIND_OPCODE_SET_ADDEND           = 0x60;
    static constexpr uint8_t BIND_OPCODE_SET_SEGMENT_AND_OFFSET = 0x70;
    static constexpr uint8_t BIND_OPCODE_ADD_ADDR_ULEB        = 0x80;
    static constexpr uint8_t BIND_OPCODE_DO_BIND              = 0x90;
    static constexpr uint8_t BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0;
    static constexpr uint8_t BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0;
    static constexpr uint8_t BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING = 0xC0;
    static constexpr uint8_t BIND_OPCODE_THREADED             = 0xD0;

    std::string symbol_name;
    int64_t  lib_ordinal = 0;
    uint64_t address = 0;
    size_t   ptr_size = is64_ ? 8 : 4;

    while (p < end) {
        uint8_t byte = *p++;
        uint8_t opcode    = byte & BIND_OPCODE_MASK;
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        size_t bytes;

        switch (opcode) {
        case BIND_OPCODE_DONE:
            if (bind_type == "lazy_bind") continue; // lazy bind uses DONE as separator
            return;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            lib_ordinal = immediate;
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            lib_ordinal = static_cast<int64_t>(read_uleb128(p, end, bytes));
            p += bytes;
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL:
            lib_ordinal = (immediate == 0) ? 0 : static_cast<int8_t>(0xF0 | immediate);
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING:
            symbol_name.clear();
            while (p < end && *p != 0) {
                symbol_name.push_back(static_cast<char>(*p++));
            }
            if (p < end) ++p;
            break;
        case BIND_OPCODE_SET_TYPE:
            break;
        case BIND_OPCODE_SET_ADDEND:
            read_uleb128(p, end, bytes); p += bytes;
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET:
            address = read_uleb128(p, end, bytes); p += bytes;
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            address += read_uleb128(p, end, bytes); p += bytes;
            break;
        case BIND_OPCODE_DO_BIND:
            if (!symbol_name.empty()) {
                SymbolInfo si;
                si.name    = symbol_name;
                si.rva     = address;
                si.source  = "import(" + bind_type + ")";
                si.type    = "function";
                if (lib_ordinal > 0 && lib_ordinal <= (int64_t)imported_libs_.size()) {
                    si.library = imported_libs_[lib_ordinal - 1];
                }
                symbols_.push_back(std::move(si));
            }
            address += ptr_size;
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            if (!symbol_name.empty()) {
                SymbolInfo si;
                si.name    = symbol_name;
                si.rva     = address;
                si.source  = "import(" + bind_type + ")";
                si.type    = "function";
                if (lib_ordinal > 0 && lib_ordinal <= (int64_t)imported_libs_.size()) {
                    si.library = imported_libs_[lib_ordinal - 1];
                }
                symbols_.push_back(std::move(si));
            }
            address += ptr_size + read_uleb128(p, end, bytes);
            p += bytes;
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            if (!symbol_name.empty()) {
                SymbolInfo si;
                si.name    = symbol_name;
                si.rva     = address;
                si.source  = "import(" + bind_type + ")";
                si.type    = "function";
                if (lib_ordinal > 0 && lib_ordinal <= (int64_t)imported_libs_.size()) {
                    si.library = imported_libs_[lib_ordinal - 1];
                }
                symbols_.push_back(std::move(si));
            }
            address += ptr_size + immediate * ptr_size;
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING: {
            uint64_t count = read_uleb128(p, end, bytes); p += bytes;
            uint64_t skip  = read_uleb128(p, end, bytes); p += bytes;
            for (uint64_t j = 0; j < count; ++j) {
                if (!symbol_name.empty()) {
                    SymbolInfo si;
                    si.name    = symbol_name;
                    si.rva     = address;
                    si.source  = "import(" + bind_type + ")";
                    si.type    = "function";
                    if (lib_ordinal > 0 && lib_ordinal <= (int64_t)imported_libs_.size()) {
                        si.library = imported_libs_[lib_ordinal - 1];
                    }
                    symbols_.push_back(std::move(si));
                }
                address += ptr_size + skip;
            }
            break;
        }
        case BIND_OPCODE_THREADED:
            // Skip threaded bind opcodes for now (iOS 13.4+)
            if (immediate == 1) { // BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB
                read_uleb128(p, end, bytes); p += bytes;
            }
            break;
        default:
            break;
        }
    }
}

} // namespace sd
