#pragma once

#include "core/types.h"
#include <cstdint>

namespace sd {

// ---- ELF format structures (portable) ----
#pragma pack(push, 1)

static constexpr uint8_t ELF_MAGIC[] = {0x7f, 'E', 'L', 'F'};

// ELF identification indices
static constexpr int EI_CLASS   = 4;
static constexpr int EI_DATA    = 5;
static constexpr int EI_NIDENT  = 16;

static constexpr uint8_t ELFCLASS32 = 1;
static constexpr uint8_t ELFCLASS64 = 2;
static constexpr uint8_t ELFDATA2LSB = 1;
static constexpr uint8_t ELFDATA2MSB = 2;

// Section types
static constexpr uint32_t SHT_SYMTAB  = 2;
static constexpr uint32_t SHT_STRTAB  = 3;
static constexpr uint32_t SHT_RELA    = 4;
static constexpr uint32_t SHT_DYNAMIC = 6;
static constexpr uint32_t SHT_REL     = 9;
static constexpr uint32_t SHT_DYNSYM  = 11;
static constexpr uint32_t SHT_GNU_HASH = 0x6ffffff6;

// Symbol binding
static constexpr uint8_t STB_LOCAL  = 0;
static constexpr uint8_t STB_GLOBAL = 1;
static constexpr uint8_t STB_WEAK   = 2;

// Symbol type
static constexpr uint8_t STT_NOTYPE  = 0;
static constexpr uint8_t STT_OBJECT  = 1;
static constexpr uint8_t STT_FUNC    = 2;
static constexpr uint8_t STT_SECTION = 3;
static constexpr uint8_t STT_FILE    = 4;

// Dynamic tags
static constexpr int64_t DT_NULL     = 0;
static constexpr int64_t DT_NEEDED   = 1;
static constexpr int64_t DT_STRTAB   = 5;
static constexpr int64_t DT_SYMTAB   = 6;
static constexpr int64_t DT_STRSZ    = 10;
static constexpr int64_t DT_JMPREL   = 23;

// Special section index
static constexpr uint16_t SHN_UNDEF = 0;

struct Elf32_Ehdr {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
};

struct Elf64_Ehdr {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
};

// Program header types
static constexpr uint32_t PT_LOAD = 1;

struct Elf32_Phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr, p_paddr;
    uint32_t p_filesz, p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr, p_paddr;
    uint64_t p_filesz, p_memsz;
    uint64_t p_align;
};

struct Elf32_Shdr {
    uint32_t sh_name, sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint32_t sh_addralign, sh_entsize;
};

struct Elf64_Shdr {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
};

struct Elf32_Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf32_Dyn {
    int32_t  d_tag;
    uint32_t d_val;
};

struct Elf64_Dyn {
    int64_t  d_tag;
    uint64_t d_val;
};

struct Elf32_Rel {
    uint32_t r_offset;
    uint32_t r_info;
};

struct Elf32_Rela {
    uint32_t r_offset;
    uint32_t r_info;
    int32_t  r_addend;
};

struct Elf64_Rel {
    uint64_t r_offset;
    uint64_t r_info;
};

struct Elf64_Rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

#pragma pack(pop)

inline uint8_t ELF32_ST_BIND(uint8_t i) { return i >> 4; }
inline uint8_t ELF32_ST_TYPE(uint8_t i) { return i & 0xf; }
inline uint32_t ELF32_R_SYM(uint32_t i) { return i >> 8; }
inline uint32_t ELF64_R_SYM(uint64_t i) { return static_cast<uint32_t>(i >> 32); }

// ---- ELF Parser ----
class ElfParser {
public:
    bool parse(const FileData& file);
    const std::vector<SymbolInfo>& symbols() const { return symbols_; }
    const std::vector<std::string>& needed_libs() const { return needed_libs_; }
    bool is64bit() const { return is64_; }
    uint64_t image_base() const { return image_base_; }

private:
    void parse_symtab(const FileData& file, size_t sym_off, size_t sym_size,
                      size_t str_off, size_t str_size, const std::string& source);
    void parse_dynamic(const FileData& file);
    void parse_relocations(const FileData& file);

    std::string get_section_name(const FileData& file, uint32_t name_idx) const;

    struct SectionInfo {
        uint32_t type;
        uint64_t offset, size, addr;
        uint32_t link, info;
        uint64_t entsize;
        std::string name;
    };

    std::vector<SectionInfo>   sections_;
    std::vector<SymbolInfo>    symbols_;
    std::vector<std::string>   needed_libs_;
    size_t                     shstrtab_off_ = 0;
    size_t                     shstrtab_size_ = 0;
    bool                       is64_ = false;
    bool                       is_le_ = true;
    uint64_t                   image_base_ = 0;
};

} // namespace sd
