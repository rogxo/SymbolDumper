#pragma once

#include "core/types.h"
#include <cstdint>

namespace sd {

// ---- PE format structures (portable, no Windows headers needed) ----
#pragma pack(push, 1)

struct PE_DOS_Header {
    uint16_t e_magic;       // 'MZ'
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;      // Offset to PE signature
};

struct PE_FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct PE_DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

static constexpr int PE_NUMBEROF_DIRECTORY_ENTRIES = 16;
static constexpr int PE_DIRECTORY_ENTRY_EXPORT  = 0;
static constexpr int PE_DIRECTORY_ENTRY_IMPORT  = 1;
static constexpr int PE_DIRECTORY_ENTRY_DEBUG   = 6;

struct PE_OptionalHeader32 {
    uint16_t Magic; // 0x10b
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode, BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage, SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit;
    uint32_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PE_DataDirectory DataDirectory[PE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct PE_OptionalHeader64 {
    uint16_t Magic; // 0x20b
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage, SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit;
    uint64_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PE_DataDirectory DataDirectory[PE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct PE_NTHeaders32 {
    uint32_t          Signature; // 'PE\0\0'
    PE_FileHeader     FileHeader;
    PE_OptionalHeader32 OptionalHeader;
};

struct PE_NTHeaders64 {
    uint32_t          Signature;
    PE_FileHeader     FileHeader;
    PE_OptionalHeader64 OptionalHeader;
};

struct PE_SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct PE_ExportDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

struct PE_ImportDescriptor {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct PE_DebugDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};

static constexpr uint32_t PE_DEBUG_TYPE_CODEVIEW = 2;

struct PE_CV_INFO_PDB70 {
    uint32_t CvSignature; // 'RSDS'
    uint8_t  Guid[16];
    uint32_t Age;
    // char PdbFileName[] follows
};

#pragma pack(pop)

// ---- PE Parser ----
class PeParser {
public:
    bool parse(const FileData& file);
    const std::vector<SymbolInfo>& symbols() const { return symbols_; }
    bool is64bit() const { return is64_; }
    uint64_t image_base() const { return image_base_; }
    std::string pdb_path() const { return pdb_path_; }

private:
    size_t rva_to_offset(uint32_t rva) const;
    void parse_exports(const FileData& file);
    void parse_imports(const FileData& file);
    void parse_debug(const FileData& file);

    std::vector<PE_SectionHeader> sections_;
    std::vector<SymbolInfo>       symbols_;
    PE_DataDirectory              data_dirs_[PE_NUMBEROF_DIRECTORY_ENTRIES] = {};
    bool                          is64_ = false;
    uint64_t                      image_base_ = 0;
    std::string                   pdb_path_;
};

} // namespace sd
