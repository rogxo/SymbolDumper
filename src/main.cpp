#include "core/types.h"
#include "core/json_writer.h"
#include "parser/binary_parser.h"
#include "platform/process_enum.h"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <set>

namespace fs = std::filesystem;

// ---- Dump configuration ----
struct DumpOptions {
    bool exports    = false;
    bool imports    = false;
    bool symtab     = false;
    bool dynsym     = false;
    bool all        = false;
    bool verbose    = false;
    bool libs       = false; // show imported libraries

    // Returns true if a symbol's source passes the filter
    bool should_include(const std::string& source) const {
        if (all) return true;

        if (exports) {
            if (source == "export_table" || source == "export_trie")
                return true;
        }
        if (imports) {
            if (source == "import_table" || source.find("import(") == 0)
                return true;
        }
        if (symtab) {
            if (source == "symtab" || source == "import(symtab)")
                return true;
        }
        if (dynsym) {
            if (source == "dynsym" || source == "import(dynsym)")
                return true;
        }
        return false;
    }

    // Filter a symbol list in place
    std::vector<sd::SymbolInfo> filter(const std::vector<sd::SymbolInfo>& symbols) const {
        if (all) return symbols;
        std::vector<sd::SymbolInfo> out;
        for (auto& s : symbols) {
            if (should_include(s.source)) out.push_back(s);
        }
        return out;
    }

    std::string describe() const {
        if (all) return "all";
        std::string d;
        if (exports) { if (!d.empty()) d += "+"; d += "exports"; }
        if (imports) { if (!d.empty()) d += "+"; d += "imports"; }
        if (symtab)  { if (!d.empty()) d += "+"; d += "symtab"; }
        if (dynsym)  { if (!d.empty()) d += "+"; d += "dynsym"; }
        return d.empty() ? "none" : d;
    }
};

static void print_usage(const char* prog) {
    std::cout
        << "SymbolDumper - Cross-process module & symbol dumper\n\n"
        << "Usage:\n"
        << "  " << prog << " --pid <PID>   [options]    Dump from a running process\n"
        << "  " << prog << " --name <name> [options]    Find process by name and dump\n"
        << "  " << prog << " --file <path> [options]    Parse a single binary file\n"
        << "  " << prog << " --list                     List all running processes\n"
        << "\nTarget Options:\n"
        << "  -p, --pid <PID>        Target process ID\n"
        << "  -n, --name <name>      Target process name (case-insensitive partial match)\n"
        << "  -f, --file <path>      Parse a binary file (PE/ELF/Mach-O)\n"
        << "  -o, --output <dir>     Output directory (default: ./output)\n"
        << "  -l, --list             List all running processes\n"
        << "\nSymbol Filters (default: --exports --imports):\n"
        << "  -E, --exports          Include export table symbols\n"
        << "  -I, --imports          Include import table symbols\n"
        << "  -S, --symtab           Include .symtab symbols (ELF/Mach-O)\n"
        << "  -D, --dynsym           Include .dynsym symbols (ELF)\n"
        << "  -A, --all              Include ALL symbol sources\n"
        << "  --libs                 Show imported library list\n"
        << "\nOther:\n"
        << "  -v, --verbose          Verbose output\n"
        << "  -h, --help             Show this help\n"
        << "\nExamples:\n"
        << "  " << prog << " --pid 1234\n"
        << "  " << prog << " --name explorer --all -o ./dump\n"
        << "  " << prog << " --file ntdll.dll --exports --symtab\n"
        << "  " << prog << " -f libc.so -A -v\n"
        << std::endl;
}

static std::vector<sd::SymbolInfo> apply_filter(
    const sd::ParseResult& result, const DumpOptions& opts, uint64_t base_addr) {
    auto filtered = opts.filter(result.symbols);
    for (auto& sym : filtered) {
        sym.address = base_addr + sym.rva;
    }
    return filtered;
}

static void dump_process(uint32_t pid, const std::string& output_dir,
                          const DumpOptions& opts) {
    std::cout << "[*] Enumerating modules for PID " << pid << "...\n";

    sd::ProcessInfo proc;
    if (!sd::enumerate_modules(pid, proc)) {
        std::cerr << "[!] Failed to enumerate modules for PID " << pid << "\n";
        std::cerr << "    Make sure you have sufficient permissions (run as admin/root).\n";
        return;
    }

    std::cout << "[+] Process: " << proc.name << " (PID: " << proc.pid << ")\n";
    std::cout << "[+] Found " << proc.modules.size() << " modules\n";
    std::cout << "[+] Symbol filter: " << opts.describe() << "\n";

    fs::create_directories(output_dir);

    std::vector<sd::ModuleSymbols> all_symbols;
    size_t total_syms = 0;
    size_t total_raw = 0;

    for (auto& mod : proc.modules) {
        if (opts.verbose) {
            std::cout << "  [*] Parsing: " << mod.name
                      << " @ " << sd::to_hex(mod.base_address) << "\n";
        }

        sd::ParseResult result = sd::parse_binary(mod.path);
        if (!result.success) {
            if (opts.verbose) {
                std::cout << "      [!] Failed to parse (format: "
                          << sd::format_name(result.format) << ")\n";
            }
            continue;
        }

        total_raw += result.symbols.size();

        sd::ModuleSymbols ms;
        ms.module = mod;
        ms.symbols = apply_filter(result, opts, mod.base_address);

        if (opts.verbose) {
            std::cout << "      [+] " << sd::format_name(result.format)
                      << (result.is64 ? " (64-bit)" : " (32-bit)")
                      << " - " << ms.symbols.size() << "/" << result.symbols.size()
                      << " symbols";
            if (!result.pdb_path.empty())
                std::cout << " [PDB: " << result.pdb_path << "]";
            std::cout << "\n";
        }

        total_syms += ms.symbols.size();
        all_symbols.push_back(std::move(ms));
    }

    // Write JSON files
    std::string modules_path = (fs::path(output_dir) / "modules.json").string();
    std::string symbols_path = (fs::path(output_dir) / "symbols.json").string();

    if (sd::write_modules_json(modules_path, proc)) {
        std::cout << "[+] Modules saved to: " << modules_path << "\n";
    } else {
        std::cerr << "[!] Failed to write modules.json\n";
    }

    if (sd::write_symbols_json(symbols_path, proc, all_symbols)) {
        std::cout << "[+] Symbols saved to: " << symbols_path << "\n";
    } else {
        std::cerr << "[!] Failed to write symbols.json\n";
    }

    std::cout << "[+] Total: " << proc.modules.size() << " modules, "
              << total_syms << " symbols (filtered from " << total_raw << ")\n";
}

static void dump_file(const std::string& filepath, const std::string& output_dir,
                       const DumpOptions& opts) {
    std::cout << "[*] Parsing file: " << filepath << "\n";

    sd::ParseResult result = sd::parse_binary(filepath);
    if (!result.success) {
        std::cerr << "[!] Failed to parse file (format: "
                  << sd::format_name(result.format) << ")\n";
        return;
    }

    std::cout << "[+] Format: " << sd::format_name(result.format)
              << (result.is64 ? " (64-bit)" : " (32-bit)") << "\n";
    std::cout << "[+] Image base: " << sd::to_hex(result.image_base) << "\n";
    std::cout << "[+] Symbol filter: " << opts.describe() << "\n";

    auto filtered = apply_filter(result, opts, result.image_base);
    std::cout << "[+] Symbols: " << filtered.size()
              << " (filtered from " << result.symbols.size() << ")\n";

    if (!result.pdb_path.empty()) {
        std::cout << "[+] PDB path: " << result.pdb_path << "\n";
    }
    if (opts.libs && !result.imported_libs.empty()) {
        std::cout << "[+] Imported libraries (" << result.imported_libs.size() << "):\n";
        for (auto& lib : result.imported_libs) {
            std::cout << "      " << lib << "\n";
        }
    }

    fs::create_directories(output_dir);

    fs::path fpath(filepath);
    std::string basename = fpath.stem().string();

    sd::ProcessInfo proc;
    proc.pid  = 0;
    proc.name = fpath.filename().string();

    sd::ModuleInfo mod;
    mod.name = fpath.filename().string();
    mod.path = filepath;
    mod.base_address = result.image_base;
    proc.modules.push_back(mod);

    sd::ModuleSymbols ms;
    ms.module  = mod;
    ms.symbols = std::move(filtered);

    std::vector<sd::ModuleSymbols> all_symbols;
    all_symbols.push_back(std::move(ms));

    std::string modules_path = (fs::path(output_dir) / (basename + "_modules.json")).string();
    std::string symbols_path = (fs::path(output_dir) / (basename + "_symbols.json")).string();

    if (sd::write_modules_json(modules_path, proc)) {
        std::cout << "[+] Modules saved to: " << modules_path << "\n";
    }
    if (sd::write_symbols_json(symbols_path, proc, all_symbols)) {
        std::cout << "[+] Symbols saved to: " << symbols_path << "\n";
    }
}

static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    }
    return true;
}

static bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.size() > haystack.size()) return false;
    for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (tolower((unsigned char)haystack[i+j]) != tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string output_dir = "./output";
    std::string target_file;
    std::string target_name;
    uint32_t target_pid = 0;
    bool do_list = false;
    DumpOptions opts;
    bool any_filter = false; // track if user explicitly set a filter

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if ((strcmp(arg, "--pid") == 0 || strcmp(arg, "-p") == 0) && i + 1 < argc) {
            target_pid = static_cast<uint32_t>(atoi(argv[++i]));
        } else if ((strcmp(arg, "--name") == 0 || strcmp(arg, "-n") == 0) && i + 1 < argc) {
            target_name = argv[++i];
        } else if ((strcmp(arg, "--file") == 0 || strcmp(arg, "-f") == 0) && i + 1 < argc) {
            target_file = argv[++i];
        } else if ((strcmp(arg, "--output") == 0 || strcmp(arg, "-o") == 0) && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(arg, "--list") == 0 || strcmp(arg, "-l") == 0) {
            do_list = true;
        } else if (strcmp(arg, "--exports") == 0 || strcmp(arg, "-E") == 0) {
            opts.exports = true; any_filter = true;
        } else if (strcmp(arg, "--imports") == 0 || strcmp(arg, "-I") == 0) {
            opts.imports = true; any_filter = true;
        } else if (strcmp(arg, "--symtab") == 0 || strcmp(arg, "-S") == 0) {
            opts.symtab = true; any_filter = true;
        } else if (strcmp(arg, "--dynsym") == 0 || strcmp(arg, "-D") == 0) {
            opts.dynsym = true; any_filter = true;
        } else if (strcmp(arg, "--all") == 0 || strcmp(arg, "-A") == 0) {
            opts.all = true; any_filter = true;
        } else if (strcmp(arg, "--libs") == 0) {
            opts.libs = true;
        } else if (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0) {
            opts.verbose = true;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "[!] Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Default filter: exports + imports
    if (!any_filter) {
        opts.exports = true;
        opts.imports = true;
    }

    // Process listing
    if (do_list) {
        auto procs = sd::list_processes();
        std::sort(procs.begin(), procs.end(),
                  [](const sd::ProcessEntry& a, const sd::ProcessEntry& b) {
                      return a.pid < b.pid;
                  });

        // If a name filter is given with --list, filter the list
        if (!target_name.empty()) {
            std::cout << "PID\tName (matching \"" << target_name << "\")\n";
            std::cout << "----\t----\n";
            int count = 0;
            for (auto& p : procs) {
                if (icontains(p.name, target_name)) {
                    std::cout << p.pid << "\t" << p.name << "\n";
                    ++count;
                }
            }
            std::cout << "\nMatched: " << count << " / " << procs.size() << " processes\n";
        } else {
            std::cout << "PID\tName\n";
            std::cout << "----\t----\n";
            for (auto& p : procs) {
                std::cout << p.pid << "\t" << p.name << "\n";
            }
            std::cout << "\nTotal: " << procs.size() << " processes\n";
        }
        return 0;
    }

    // Find PID by name if --name is used
    if (target_pid == 0 && !target_name.empty()) {
        auto procs = sd::list_processes();
        std::vector<sd::ProcessEntry> matches;

        for (auto& p : procs) {
            if (iequals(p.name, target_name) ||
                iequals(p.name, target_name + ".exe")) {
                matches.push_back(p);
            }
        }

        // Fallback to partial match
        if (matches.empty()) {
            for (auto& p : procs) {
                if (icontains(p.name, target_name)) {
                    matches.push_back(p);
                }
            }
        }

        if (matches.empty()) {
            std::cerr << "[!] No process found matching \"" << target_name << "\"\n";
            return 1;
        }

        if (matches.size() > 1) {
            std::cout << "[*] Multiple processes match \"" << target_name << "\":\n";
            for (auto& m : matches) {
                std::cout << "    PID " << m.pid << "  " << m.name << "\n";
            }
            std::cout << "[*] Using first match: PID " << matches[0].pid << "\n";
        }

        target_pid = matches[0].pid;
    }

    // Execute
    if (target_pid > 0) {
        dump_process(target_pid, output_dir, opts);
    } else if (!target_file.empty()) {
        dump_file(target_file, output_dir, opts);
    } else {
        std::cerr << "[!] No target specified. Use --pid, --name, or --file.\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
