#include "parser/elf_parser.h"
#include <algorithm>
#include <cstring>

namespace sd {

std::string ElfParser::get_section_name(const FileData& file, uint32_t name_idx) const {
    if (shstrtab_off_ == 0 || name_idx >= shstrtab_size_) return "";
    return file.read_string(shstrtab_off_ + name_idx);
}

static std::string elf_sym_type_str(uint8_t st_info) {
    switch (ELF32_ST_TYPE(st_info)) {
        case STT_FUNC:    return "function";
        case STT_OBJECT:  return "object";
        case STT_SECTION: return "section";
        case STT_FILE:    return "file";
        default:          return "unknown";
    }
}

bool ElfParser::parse(const FileData& file) {
    symbols_.clear();
    sections_.clear();
    needed_libs_.clear();

    if (file.size() < EI_NIDENT) return false;
    auto ident = file.raw(0);
    if (memcmp(ident, ELF_MAGIC, 4) != 0) return false;

    is64_ = (ident[EI_CLASS] == ELFCLASS64);
    is_le_ = (ident[EI_DATA] == ELFDATA2LSB);
    // Note: we assume host is little-endian for now (covers x86/ARM LE)

    uint16_t e_shnum, e_shstrndx, e_shentsize;
    uint64_t e_shoff;

    uint64_t e_phoff;
    uint16_t e_phnum, e_phentsize;

    if (is64_) {
        auto ehdr = file.at<Elf64_Ehdr>(0);
        if (!ehdr) return false;
        e_shoff     = ehdr->e_shoff;
        e_shnum     = ehdr->e_shnum;
        e_shstrndx  = ehdr->e_shstrndx;
        e_shentsize = ehdr->e_shentsize;
        e_phoff     = ehdr->e_phoff;
        e_phnum     = ehdr->e_phnum;
        e_phentsize = ehdr->e_phentsize;
    } else {
        auto ehdr = file.at<Elf32_Ehdr>(0);
        if (!ehdr) return false;
        e_shoff     = ehdr->e_shoff;
        e_shnum     = ehdr->e_shnum;
        e_shstrndx  = ehdr->e_shstrndx;
        e_shentsize = ehdr->e_shentsize;
        e_phoff     = ehdr->e_phoff;
        e_phnum     = ehdr->e_phnum;
        e_phentsize = ehdr->e_phentsize;
    }

    // Extract image base from first PT_LOAD segment
    image_base_ = 0;
    for (uint16_t i = 0; i < e_phnum; ++i) {
        size_t ph_off = static_cast<size_t>(e_phoff) + i * e_phentsize;
        if (is64_) {
            auto ph = file.at<Elf64_Phdr>(ph_off);
            if (ph && ph->p_type == PT_LOAD) {
                image_base_ = ph->p_vaddr - ph->p_offset;
                break;
            }
        } else {
            auto ph = file.at<Elf32_Phdr>(ph_off);
            if (ph && ph->p_type == PT_LOAD) {
                image_base_ = ph->p_vaddr - ph->p_offset;
                break;
            }
        }
    }

    // Read section headers
    for (uint16_t i = 0; i < e_shnum; ++i) {
        SectionInfo si{};
        size_t off = static_cast<size_t>(e_shoff) + i * e_shentsize;
        if (is64_) {
            auto sh = file.at<Elf64_Shdr>(off);
            if (!sh) continue;
            si.type    = sh->sh_type;
            si.offset  = sh->sh_offset;
            si.size    = sh->sh_size;
            si.addr    = sh->sh_addr;
            si.link    = sh->sh_link;
            si.info    = sh->sh_info;
            si.entsize = sh->sh_entsize;
        } else {
            auto sh = file.at<Elf32_Shdr>(off);
            if (!sh) continue;
            si.type    = sh->sh_type;
            si.offset  = sh->sh_offset;
            si.size    = sh->sh_size;
            si.addr    = sh->sh_addr;
            si.link    = sh->sh_link;
            si.info    = sh->sh_info;
            si.entsize = sh->sh_entsize;
        }
        // We'll fill in names after we have shstrtab
        sections_.push_back(si);
    }

    // Get shstrtab
    if (e_shstrndx < sections_.size()) {
        shstrtab_off_  = static_cast<size_t>(sections_[e_shstrndx].offset);
        shstrtab_size_ = static_cast<size_t>(sections_[e_shstrndx].size);
    }

    // Re-read section name indices and assign names
    for (uint16_t i = 0; i < e_shnum; ++i) {
        size_t off = static_cast<size_t>(e_shoff) + i * e_shentsize;
        uint32_t sh_name = 0;
        if (is64_) {
            auto sh = file.at<Elf64_Shdr>(off);
            if (sh) sh_name = sh->sh_name;
        } else {
            auto sh = file.at<Elf32_Shdr>(off);
            if (sh) sh_name = sh->sh_name;
        }
        if (i < sections_.size()) {
            sections_[i].name = get_section_name(file, sh_name);
        }
    }

    // Parse symbol tables
    for (size_t i = 0; i < sections_.size(); ++i) {
        auto& sec = sections_[i];
        if (sec.type == SHT_SYMTAB || sec.type == SHT_DYNSYM) {
            // Link field points to the associated string table section
            size_t str_off = 0, str_size = 0;
            if (sec.link < sections_.size()) {
                str_off  = static_cast<size_t>(sections_[sec.link].offset);
                str_size = static_cast<size_t>(sections_[sec.link].size);
            }
            std::string source = (sec.type == SHT_DYNSYM) ? "dynsym" : "symtab";
            if (!sec.name.empty()) source = sec.name.substr(0, 1) == "." ? sec.name.substr(1) : sec.name;
            parse_symtab(file, static_cast<size_t>(sec.offset),
                        static_cast<size_t>(sec.size),
                        str_off, str_size, source);
        }
    }

    parse_dynamic(file);
    parse_relocations(file);

    return true;
}

void ElfParser::parse_symtab(const FileData& file, size_t sym_off, size_t sym_size,
                              size_t str_off, size_t str_size, const std::string& source) {
    if (sym_off == 0 || sym_size == 0) return;

    size_t entry_size = is64_ ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
    size_t count = sym_size / entry_size;

    for (size_t i = 0; i < count; ++i) {
        size_t off = sym_off + i * entry_size;
        uint32_t st_name;
        uint64_t st_value, st_size_val;
        uint8_t  st_info;
        uint16_t st_shndx;

        if (is64_) {
            auto sym = file.at<Elf64_Sym>(off);
            if (!sym) break;
            st_name     = sym->st_name;
            st_value    = sym->st_value;
            st_size_val = sym->st_size;
            st_info     = sym->st_info;
            st_shndx    = sym->st_shndx;
        } else {
            auto sym = file.at<Elf32_Sym>(off);
            if (!sym) break;
            st_name     = sym->st_name;
            st_value    = sym->st_value;
            st_size_val = sym->st_size;
            st_info     = sym->st_info;
            st_shndx    = sym->st_shndx;
        }

        // Skip null symbols
        if (st_name == 0 && st_value == 0) continue;

        std::string name;
        if (str_off > 0 && st_name < str_size) {
            name = file.read_string(str_off + st_name);
        }
        if (name.empty()) continue;

        SymbolInfo si;
        si.name     = name;
        si.rva      = st_value;
        si.sym_size = st_size_val;
        si.type     = elf_sym_type_str(st_info);
        si.source   = source;

        // Determine if this is an import (undefined symbol)
        if (st_shndx == SHN_UNDEF && st_value == 0) {
            si.source = "import(" + source + ")";
        }

        symbols_.push_back(std::move(si));
    }
}

void ElfParser::parse_dynamic(const FileData& file) {
    for (auto& sec : sections_) {
        if (sec.type != SHT_DYNAMIC) continue;

        // Find dynamic string table
        size_t dynstr_off = 0, dynstr_size = 0;
        if (sec.link < sections_.size()) {
            dynstr_off  = static_cast<size_t>(sections_[sec.link].offset);
            dynstr_size = static_cast<size_t>(sections_[sec.link].size);
        }

        size_t entry_size = is64_ ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
        size_t count = static_cast<size_t>(sec.size) / entry_size;

        for (size_t i = 0; i < count; ++i) {
            size_t off = static_cast<size_t>(sec.offset) + i * entry_size;
            int64_t tag;
            uint64_t val;

            if (is64_) {
                auto dyn = file.at<Elf64_Dyn>(off);
                if (!dyn) break;
                tag = dyn->d_tag;
                val = dyn->d_val;
            } else {
                auto dyn = file.at<Elf32_Dyn>(off);
                if (!dyn) break;
                tag = dyn->d_tag;
                val = dyn->d_val;
            }

            if (tag == DT_NULL) break;

            if (tag == DT_NEEDED && dynstr_off > 0 && val < dynstr_size) {
                std::string lib = file.read_string(dynstr_off + static_cast<size_t>(val));
                if (!lib.empty()) needed_libs_.push_back(lib);
            }
        }
    }
}

void ElfParser::parse_relocations(const FileData& file) {
    // Parse relocation sections to find imported symbols with their GOT/PLT addresses
    for (auto& sec : sections_) {
        if (sec.type != SHT_REL && sec.type != SHT_RELA) continue;

        // The link field points to the associated symbol table
        // The info field points to the section to which the relocations apply
        if (sec.link >= sections_.size()) continue;

        auto& sym_sec = sections_[sec.link];
        size_t sym_str_off = 0, sym_str_size = 0;
        if (sym_sec.link < sections_.size()) {
            sym_str_off  = static_cast<size_t>(sections_[sym_sec.link].offset);
            sym_str_size = static_cast<size_t>(sections_[sym_sec.link].size);
        }

        bool is_rela = (sec.type == SHT_RELA);

        if (is64_) {
            size_t entry_size = is_rela ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
            size_t count = static_cast<size_t>(sec.size) / entry_size;
            for (size_t i = 0; i < count; ++i) {
                size_t off = static_cast<size_t>(sec.offset) + i * entry_size;
                uint64_t r_offset, r_info;
                if (is_rela) {
                    auto r = file.at<Elf64_Rela>(off);
                    if (!r) break;
                    r_offset = r->r_offset;
                    r_info   = r->r_info;
                } else {
                    auto r = file.at<Elf64_Rel>(off);
                    if (!r) break;
                    r_offset = r->r_offset;
                    r_info   = r->r_info;
                }
                uint32_t sym_idx = ELF64_R_SYM(r_info);
                // Read symbol name
                size_t sym_off = static_cast<size_t>(sym_sec.offset) + sym_idx * sizeof(Elf64_Sym);
                auto sym = file.at<Elf64_Sym>(sym_off);
                if (!sym || sym->st_name == 0) continue;
                if (sym->st_name < sym_str_size) {
                    std::string name = file.read_string(sym_str_off + sym->st_name);
                    if (name.empty()) continue;
                    // We already have this symbol from parse_symtab, but we can
                    // add relocation address info. For now, we skip duplicates.
                    // The relocation entries mainly confirm import relationships.
                }
            }
        } else {
            size_t entry_size = is_rela ? sizeof(Elf32_Rela) : sizeof(Elf32_Rel);
            size_t count = static_cast<size_t>(sec.size) / entry_size;
            for (size_t i = 0; i < count; ++i) {
                size_t off = static_cast<size_t>(sec.offset) + i * entry_size;
                uint32_t r_offset, r_info;
                if (is_rela) {
                    auto r = file.at<Elf32_Rela>(off);
                    if (!r) break;
                    r_offset = r->r_offset;
                    r_info   = r->r_info;
                } else {
                    auto r = file.at<Elf32_Rel>(off);
                    if (!r) break;
                    r_offset = r->r_offset;
                    r_info   = r->r_info;
                }
                // Similar to above, relocation parsing for 32-bit
                (void)r_offset;
                (void)r_info;
            }
        }
    }
}

} // namespace sd
