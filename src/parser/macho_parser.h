#pragma once

#include "core/types.h"
#include <cstdint>

namespace sd {

// ---- Mach-O format structures (portable) ----
#pragma pack(push, 1)

static constexpr uint32_t MH_MAGIC    = 0xFEEDFACE;
static constexpr uint32_t MH_MAGIC_64 = 0xFEEDFACF;
static constexpr uint32_t MH_CIGAM    = 0xCEFAEDFE;
static constexpr uint32_t MH_CIGAM_64 = 0xCFFAEDFE;
static constexpr uint32_t FAT_MAGIC   = 0xCAFEBABE;
static constexpr uint32_t FAT_CIGAM   = 0xBEBAFECA;

// Load command types
static constexpr uint32_t LC_SYMTAB          = 0x02;
static constexpr uint32_t LC_DYSYMTAB        = 0x0B;
static constexpr uint32_t LC_LOAD_DYLIB      = 0x0C;
static constexpr uint32_t LC_ID_DYLIB        = 0x0D;
static constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x80000018;
static constexpr uint32_t LC_SEGMENT         = 0x01;
static constexpr uint32_t LC_SEGMENT_64      = 0x19;
static constexpr uint32_t LC_DYLD_INFO       = 0x22;
static constexpr uint32_t LC_DYLD_INFO_ONLY  = 0x80000022;
static constexpr uint32_t LC_DYLD_EXPORTS_TRIE = 0x80000033;
static constexpr uint32_t LC_REEXPORT_DYLIB  = 0x8000001F;

// nlist type masks
static constexpr uint8_t N_STAB = 0xE0;
static constexpr uint8_t N_PEXT = 0x10;
static constexpr uint8_t N_TYPE = 0x0E;
static constexpr uint8_t N_EXT  = 0x01;

// N_TYPE values
static constexpr uint8_t N_UNDF = 0x00;
static constexpr uint8_t N_ABS  = 0x02;
static constexpr uint8_t N_SECT = 0x0E;
static constexpr uint8_t N_INDR = 0x0A;

// Export trie flags
static constexpr uint8_t EXPORT_SYMBOL_FLAGS_KIND_MASK     = 0x03;
static constexpr uint8_t EXPORT_SYMBOL_FLAGS_KIND_REGULAR  = 0x00;
static constexpr uint8_t EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01;
static constexpr uint8_t EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02;
static constexpr uint8_t EXPORT_SYMBOL_FLAGS_REEXPORT      = 0x08;
static constexpr uint8_t EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10;

struct MachO_Header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct MachO_Header64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct MachO_LoadCommand {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct MachO_SymtabCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct MachO_DysymtabCommand {
    uint32_t cmd, cmdsize;
    uint32_t ilocalsym, nlocalsym;
    uint32_t iextdefsym, nextdefsym;
    uint32_t iundefsym, nundefsym;
    uint32_t tocoff, ntoc;
    uint32_t modtaboff, nmodtab;
    uint32_t extrefsymoff, nextrefsyms;
    uint32_t indirectsymoff, nindirectsyms;
    uint32_t extreloff, nextrel;
    uint32_t locreloff, nlocrel;
};

struct MachO_DylibCommand {
    uint32_t cmd, cmdsize;
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct MachO_DyldInfoCommand {
    uint32_t cmd, cmdsize;
    uint32_t rebase_off, rebase_size;
    uint32_t bind_off, bind_size;
    uint32_t weak_bind_off, weak_bind_size;
    uint32_t lazy_bind_off, lazy_bind_size;
    uint32_t export_off, export_size;
};

struct MachO_LinkeditDataCommand {
    uint32_t cmd, cmdsize;
    uint32_t dataoff, datasize;
};

struct MachO_SegmentCommand {
    uint32_t cmd, cmdsize;
    char     segname[16];
    uint32_t vmaddr, vmsize;
    uint32_t fileoff, filesize;
    uint32_t maxprot, initprot;
    uint32_t nsects, flags;
};

struct MachO_SegmentCommand64 {
    uint32_t cmd, cmdsize;
    char     segname[16];
    uint64_t vmaddr, vmsize;
    uint64_t fileoff, filesize;
    uint32_t maxprot, initprot;
    uint32_t nsects, flags;
};

struct MachO_Nlist {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    int16_t  n_desc;
    uint32_t n_value;
};

struct MachO_Nlist64 {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

struct FatHeader {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct FatArch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

#pragma pack(pop)

// ---- Mach-O Parser ----
class MachOParser {
public:
    bool parse(const FileData& file);
    const std::vector<SymbolInfo>& symbols() const { return symbols_; }
    const std::vector<std::string>& imported_libs() const { return imported_libs_; }
    bool is64bit() const { return is64_; }
    uint64_t image_base() const { return image_base_; }

private:
    bool parse_single(const FileData& file, size_t base_offset);
    void parse_symtab(const FileData& file, size_t base_offset, const MachO_SymtabCommand& cmd);
    void parse_dysymtab(const FileData& file, size_t base_offset, const MachO_DysymtabCommand& cmd);
    void parse_export_trie(const FileData& file, size_t trie_offset, size_t trie_size);
    void walk_export_trie(const FileData& file, size_t trie_start, size_t trie_size,
                          size_t node_offset, const std::string& prefix);
    void parse_bind_info(const FileData& file, size_t bind_offset, size_t bind_size,
                         const std::string& bind_type);

    std::vector<SymbolInfo>  symbols_;
    std::vector<std::string> imported_libs_;
    bool                     is64_ = false;
    bool                     swap_ = false; // byte-swap needed?
    uint64_t                 image_base_ = 0;

    // Symtab data for dysymtab cross-referencing
    size_t symtab_off_ = 0;
    uint32_t symtab_nsyms_ = 0;
    size_t strtab_off_ = 0;
    uint32_t strtab_size_ = 0;
};

} // namespace sd
