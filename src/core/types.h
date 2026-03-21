#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace sd {

struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t    base_address = 0;
    uint64_t    size = 0;
};

struct SymbolInfo {
    std::string name;
    uint64_t    rva = 0;        // Relative Virtual Address within the module
    uint64_t    address = 0;    // Absolute address in process (base + rva)
    std::string type;           // "function", "object", "unknown"
    std::string source;         // "export_table", "import_table", "symtab", "dynsym", "pdb", etc.
    std::string library;        // For imports: the source library name
    int64_t     ordinal = -1;   // For PE exports/imports by ordinal
    uint64_t    sym_size = 0;   // Symbol size if available
};

struct ModuleSymbols {
    ModuleInfo               module;
    std::vector<SymbolInfo>  symbols;
};

struct ProcessInfo {
    uint32_t                  pid = 0;
    std::string               name;
    std::vector<ModuleInfo>   modules;
};

// File data helper: loads a binary file into memory
class FileData {
public:
    bool load(const std::string& path) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) return false;
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        if (sz <= 0) { fclose(f); return false; }
        fseek(f, 0, SEEK_SET);
        data_.resize(static_cast<size_t>(sz));
        size_t rd = fread(data_.data(), 1, data_.size(), f);
        fclose(f);
        return rd == data_.size();
    }

    template<typename T>
    const T* at(size_t offset) const {
        if (offset + sizeof(T) > data_.size()) return nullptr;
        return reinterpret_cast<const T*>(data_.data() + offset);
    }

    const uint8_t* raw(size_t offset = 0) const {
        if (offset >= data_.size()) return nullptr;
        return data_.data() + offset;
    }

    size_t size() const { return data_.size(); }

    std::string read_string(size_t offset, size_t max_len = 4096) const {
        if (offset >= data_.size()) return "";
        std::string result;
        for (size_t i = offset; i < data_.size() && i < offset + max_len; ++i) {
            if (data_[i] == 0) break;
            result.push_back(static_cast<char>(data_[i]));
        }
        return result;
    }

    template<typename T>
    T read(size_t offset) const {
        T val{};
        if (offset + sizeof(T) <= data_.size()) {
            memcpy(&val, data_.data() + offset, sizeof(T));
        }
        return val;
    }

private:
    std::vector<uint8_t> data_;
};

} // namespace sd
