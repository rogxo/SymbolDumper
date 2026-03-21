set_project("SymbolDumper")
set_version("1.0.0")
set_languages("c++17")

add_rules("mode.debug", "mode.release")
add_requires("nlohmann_json")

target("symbol_dumper")
    set_kind("binary")
    add_includedirs("src")
    add_packages("nlohmann_json")

    -- Common source files (parsers + main)
    add_files("src/main.cpp")
    add_files("src/parser/*.cpp")

    -- Platform-specific process enumeration
    if is_plat("windows") then
        add_files("src/platform/process_enum_win.cpp")
        add_syslinks("psapi", "dbghelp", "advapi32")
        add_defines("SD_PLATFORM_WINDOWS")
    elseif is_plat("linux", "android") then
        add_files("src/platform/process_enum_linux.cpp")
        add_defines("SD_PLATFORM_LINUX")
    elseif is_plat("macosx", "iphoneos") then
        add_files("src/platform/process_enum_darwin.cpp")
        add_defines("SD_PLATFORM_DARWIN")
    end
