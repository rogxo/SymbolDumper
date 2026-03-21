#include "parser/pe_parser.h"
#include <algorithm>
#include <cstring>

namespace sd {

size_t PeParser::rva_to_offset(uint32_t rva) const {
    for (auto& sec : sections_) {
        if (rva >= sec.VirtualAddress &&
            rva < sec.VirtualAddress + sec.VirtualSize) {
            return rva - sec.VirtualAddress + sec.PointerToRawData;
        }
    }
    return static_cast<size_t>(-1);
}

bool PeParser::parse(const FileData& file) {
    symbols_.clear();
    sections_.clear();
    pdb_path_.clear();

    if (file.size() < sizeof(PE_DOS_Header)) return false;

    auto dos = file.at<PE_DOS_Header>(0);
    if (!dos || dos->e_magic != 0x5A4D) return false; // 'MZ'

    size_t pe_off = static_cast<size_t>(dos->e_lfanew);
    if (pe_off + 4 + sizeof(PE_FileHeader) > file.size()) return false;

    uint32_t sig = file.read<uint32_t>(pe_off);
    if (sig != 0x00004550) return false; // 'PE\0\0'

    auto fh = file.at<PE_FileHeader>(pe_off + 4);
    if (!fh) return false;

    size_t opt_off = pe_off + 4 + sizeof(PE_FileHeader);
    uint16_t opt_magic = file.read<uint16_t>(opt_off);

    uint16_t num_sections = fh->NumberOfSections;
    size_t sec_off = opt_off + fh->SizeOfOptionalHeader;

    if (opt_magic == 0x20b) {
        // PE32+ (64-bit)
        is64_ = true;
        auto opt = file.at<PE_OptionalHeader64>(opt_off);
        if (!opt) return false;
        image_base_ = opt->ImageBase;
        uint32_t n = std::min(opt->NumberOfRvaAndSizes, (uint32_t)PE_NUMBEROF_DIRECTORY_ENTRIES);
        memcpy(data_dirs_, opt->DataDirectory, n * sizeof(PE_DataDirectory));
    } else if (opt_magic == 0x10b) {
        // PE32 (32-bit)
        is64_ = false;
        auto opt = file.at<PE_OptionalHeader32>(opt_off);
        if (!opt) return false;
        image_base_ = opt->ImageBase;
        uint32_t n = std::min(opt->NumberOfRvaAndSizes, (uint32_t)PE_NUMBEROF_DIRECTORY_ENTRIES);
        memcpy(data_dirs_, opt->DataDirectory, n * sizeof(PE_DataDirectory));
    } else {
        return false;
    }

    // Read section headers
    for (uint16_t i = 0; i < num_sections; ++i) {
        auto sec = file.at<PE_SectionHeader>(sec_off + i * sizeof(PE_SectionHeader));
        if (sec) sections_.push_back(*sec);
    }

    parse_exports(file);
    parse_imports(file);
    parse_debug(file);

    return true;
}

void PeParser::parse_exports(const FileData& file) {
    auto& dd = data_dirs_[PE_DIRECTORY_ENTRY_EXPORT];
    if (dd.VirtualAddress == 0 || dd.Size == 0) return;

    size_t off = rva_to_offset(dd.VirtualAddress);
    if (off == (size_t)-1) return;

    auto exp = file.at<PE_ExportDirectory>(off);
    if (!exp) return;

    uint32_t num_funcs = exp->NumberOfFunctions;
    uint32_t num_names = exp->NumberOfNames;

    size_t funcs_off = rva_to_offset(exp->AddressOfFunctions);
    size_t names_off = rva_to_offset(exp->AddressOfNames);
    size_t ords_off  = rva_to_offset(exp->AddressOfNameOrdinals);

    if (funcs_off == (size_t)-1) return;

    // Build ordinal-to-name map
    std::vector<std::string> ordinal_names(num_funcs);
    if (names_off != (size_t)-1 && ords_off != (size_t)-1) {
        for (uint32_t i = 0; i < num_names; ++i) {
            uint32_t name_rva = file.read<uint32_t>(names_off + i * 4);
            uint16_t ord_idx  = file.read<uint16_t>(ords_off + i * 2);
            if (ord_idx < num_funcs) {
                size_t name_off = rva_to_offset(name_rva);
                if (name_off != (size_t)-1) {
                    ordinal_names[ord_idx] = file.read_string(name_off);
                }
            }
        }
    }

    uint32_t exp_dir_start = dd.VirtualAddress;
    uint32_t exp_dir_end   = dd.VirtualAddress + dd.Size;

    for (uint32_t i = 0; i < num_funcs; ++i) {
        uint32_t func_rva = file.read<uint32_t>(funcs_off + i * 4);
        if (func_rva == 0) continue;

        // Check if this is a forwarder (RVA points within export directory)
        bool is_forwarder = (func_rva >= exp_dir_start && func_rva < exp_dir_end);

        SymbolInfo sym;
        sym.rva     = func_rva;
        sym.ordinal = static_cast<int64_t>(exp->Base + i);
        sym.source  = "export_table";
        sym.type    = "function";

        if (!ordinal_names[i].empty()) {
            sym.name = ordinal_names[i];
        } else {
            sym.name = "ordinal_" + std::to_string(sym.ordinal);
        }

        if (is_forwarder) {
            size_t fwd_off = rva_to_offset(func_rva);
            if (fwd_off != (size_t)-1) {
                std::string fwd = file.read_string(fwd_off);
                sym.type = "forwarder";
                sym.library = fwd;
            }
        }

        symbols_.push_back(std::move(sym));
    }
}

void PeParser::parse_imports(const FileData& file) {
    auto& dd = data_dirs_[PE_DIRECTORY_ENTRY_IMPORT];
    if (dd.VirtualAddress == 0 || dd.Size == 0) return;

    size_t off = rva_to_offset(dd.VirtualAddress);
    if (off == (size_t)-1) return;

    for (size_t i = 0; ; ++i) {
        size_t desc_off = off + i * sizeof(PE_ImportDescriptor);
        auto desc = file.at<PE_ImportDescriptor>(desc_off);
        if (!desc) break;
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break;

        size_t name_off = rva_to_offset(desc->Name);
        std::string dll_name;
        if (name_off != (size_t)-1) {
            dll_name = file.read_string(name_off);
        }

        uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint32_t iat_rva   = desc->FirstThunk;
        size_t thunk_off = rva_to_offset(thunk_rva);
        if (thunk_off == (size_t)-1) continue;

        for (uint32_t j = 0; ; ++j) {
            SymbolInfo sym;
            sym.source  = "import_table";
            sym.library = dll_name;
            sym.type    = "function";

            if (is64_) {
                uint64_t thunk_data = file.read<uint64_t>(thunk_off + j * 8);
                if (thunk_data == 0) break;

                sym.rva = iat_rva + j * 8;

                if (thunk_data & (1ULL << 63)) {
                    // Import by ordinal
                    sym.ordinal = static_cast<int64_t>(thunk_data & 0xFFFF);
                    sym.name = dll_name + "!ordinal_" + std::to_string(sym.ordinal);
                } else {
                    size_t hint_off = rva_to_offset(static_cast<uint32_t>(thunk_data & 0x7FFFFFFF));
                    if (hint_off != (size_t)-1) {
                        // uint16_t hint = file.read<uint16_t>(hint_off);
                        sym.name = file.read_string(hint_off + 2);
                    }
                }
            } else {
                uint32_t thunk_data = file.read<uint32_t>(thunk_off + j * 4);
                if (thunk_data == 0) break;

                sym.rva = iat_rva + j * 4;

                if (thunk_data & (1U << 31)) {
                    sym.ordinal = static_cast<int64_t>(thunk_data & 0xFFFF);
                    sym.name = dll_name + "!ordinal_" + std::to_string(sym.ordinal);
                } else {
                    size_t hint_off = rva_to_offset(thunk_data & 0x7FFFFFFF);
                    if (hint_off != (size_t)-1) {
                        sym.name = file.read_string(hint_off + 2);
                    }
                }
            }

            if (!sym.name.empty()) {
                symbols_.push_back(std::move(sym));
            }
        }
    }
}

void PeParser::parse_debug(const FileData& file) {
    auto& dd = data_dirs_[PE_DIRECTORY_ENTRY_DEBUG];
    if (dd.VirtualAddress == 0 || dd.Size == 0) return;

    size_t off = rva_to_offset(dd.VirtualAddress);
    if (off == (size_t)-1) return;

    uint32_t count = dd.Size / sizeof(PE_DebugDirectory);
    for (uint32_t i = 0; i < count; ++i) {
        auto dbg = file.at<PE_DebugDirectory>(off + i * sizeof(PE_DebugDirectory));
        if (!dbg) break;

        if (dbg->Type == PE_DEBUG_TYPE_CODEVIEW && dbg->SizeOfData > sizeof(PE_CV_INFO_PDB70)) {
            size_t cv_off = dbg->PointerToRawData;
            auto cv = file.at<PE_CV_INFO_PDB70>(cv_off);
            if (cv && cv->CvSignature == 0x53445352) { // 'RSDS'
                pdb_path_ = file.read_string(cv_off + sizeof(PE_CV_INFO_PDB70));
            }
        }
    }
}

} // namespace sd
