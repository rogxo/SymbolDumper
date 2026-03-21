# SymbolDumper

跨进程模块信息与符号信息提取工具，支持 Windows / Android / iOS 平台，支持 PE / ELF / Mach-O 二进制格式。

## 功能

- **跨进程模块枚举**：在目标进程外部获取所有已加载模块的基地址、大小、路径
- **多格式符号解析**：
  - **PE**：导出表、导入表、PDB 路径
  - **ELF**：`.symtab`、`.dynsym`、`.dynamic`（DT_NEEDED）、重定位表
  - **Mach-O**：`LC_SYMTAB`、`LC_DYSYMTAB`、Export Trie、Bind Info、`LC_LOAD_DYLIB`
- **符号去重**：基于 `(name, rva)` 去重，优先保留高优先级来源
- **JSON 输出**：模块信息和符号信息分开存放（`modules.json` + `symbols.json`）
- **IDA Python 脚本**：扫描 IDA 中加载的二进制，匹配 4/8 字节指针数据并还原符号信息
- **灵活过滤**：可按符号来源（导出表、导入表、symtab、dynsym）过滤输出

## 构建

```bash
# 安装 xmake: https://xmake.io
xmake f -p windows -m release
xmake build

# Linux / Android
xmake f -p linux -m release && xmake build

# macOS / iOS
xmake f -p macosx -m release && xmake build
```

## 使用方法

### 基本命令

```bash
# 列出所有进程
symbol_dumper --list

# 按名称搜索进程
symbol_dumper --list --name explorer

# Dump 指定进程（默认只导出 exports + imports）
symbol_dumper --pid 1234

# 按进程名 dump（大小写不敏感，支持部分匹配）
symbol_dumper --name explorer

# 解析单个二进制文件
symbol_dumper --file kernel32.dll
```

### 符号过滤

默认只 dump 导入表和导出表符号。可通过以下选项控制：

```bash
symbol_dumper --pid 1234 --exports          # 仅导出表
symbol_dumper --pid 1234 --imports          # 仅导入表
symbol_dumper --file libc.so -E -S          # 导出表 + symtab
symbol_dumper --pid 1234 --all              # 所有符号源
symbol_dumper --name explorer --all -v      # 全部符号 + 详细输出
```

### 完整选项

```
Target:
  -p, --pid <PID>        目标进程 ID
  -n, --name <name>      按进程名查找（大小写不敏感）
  -f, --file <path>      解析单个二进制文件
  -o, --output <dir>     输出目录（默认 ./output）
  -l, --list             列出运行中的进程

Symbol Filters (默认 --exports --imports):
  -E, --exports          导出表符号
  -I, --imports          导入表符号
  -S, --symtab           .symtab 符号（ELF/Mach-O）
  -D, --dynsym           .dynsym 符号（ELF）
  -A, --all              所有符号源
  --libs                 显示导入库列表

Other:
  -v, --verbose          详细输出
  -h, --help             帮助
```

## 输出格式

输出两个 JSON 文件，分开存放：

### modules.json

```json
{
  "process_id": 1234,
  "process_name": "explorer.exe",
  "modules": [
    {
      "name": "kernel32.dll",
      "path": "C:\\Windows\\System32\\kernel32.dll",
      "base_address": "0x7FFB441E0000",
      "size": 688128
    }
  ]
}
```

### symbols.json

```json
{
  "process_id": 1234,
  "modules": [
    {
      "module_name": "kernel32.dll",
      "base_address": "0x7FFB441E0000",
      "symbol_count": 2896,
      "symbols": [
        {
          "name": "CreateFileW",
          "rva": "0x24EA0",
          "address": "0x7FFB44204EA0",
          "type": "function",
          "source": "export_table",
          "ordinal": 196
        }
      ]
    }
  ]
}
```

### 符号字段说明

| 字段 | 说明 |
|------|------|
| `name` | 符号名称 |
| `rva` | 相对虚拟地址（相对于模块基地址） |
| `address` | 绝对地址（进程内实际地址 = base + rva） |
| `type` | 类型：function / object / forwarder / unknown |
| `source` | 来源：export_table / import_table / symtab / dynsym / export_trie / import(bind) 等 |
| `library` | 导入符号来源库名（仅导入符号） |
| `ordinal` | PE 导出序号（仅 PE 导出符号） |
| `size` | 符号大小（如有） |

## 工具插件

### IDA Pro 脚本

`scripts/ida_symbol_resolver.py` 用于在 IDA Pro 中还原符号信息。

**使用方法：**
1. 在 IDA 中打开目标二进制
2. `File -> Script file...` 选择 `scripts/ida_symbol_resolver.py`
3. 按提示选择 `modules.json` 和 `symbols.json`
4. 选择执行模式：
   - **Full Scan**：应用符号名 + 扫描指针匹配
   - **Apply Symbols**：仅应用符号名

**工作原理：**
1. **Phase 1 - 直接符号应用**：如果当前二进制的基地址匹配某个模块，直接将符号名应用到对应的 RVA 位置
2. **Phase 2 - 指针扫描**：逐段扫描二进制数据，查找 4 字节 / 8 字节值是否匹配已知的符号地址，匹配则添加交叉引用注释
3. **可选：非对齐扫描**：逐字节扫描，捕获非对齐的指针引用（较慢）

### x64dbg 符号导入

`scripts/x64dbg_symbol_loader.py` 将 symbols.json 转换为 x64dbg 可加载的数据库文件（`.dd64`/`.dd32`）。

**使用方法：**

```bash
# 基本转换（生成 .dd64 数据库文件）
python scripts/x64dbg_symbol_loader.py

# 同时生成 x64dbg 脚本文件
python scripts/x64dbg_symbol_loader.py --script

# 指定输入/输出路径
python scripts/x64dbg_symbol_loader.py --symbols output/symbols.json --modules output/modules.json --output output/x64dbg

# 直接复制到 x64dbg 的 db 目录
python scripts/x64dbg_symbol_loader.py --dbdir "E:/Tools/x64dbg/db"
```

**加载方式：**
1. **自动加载**：将生成的 `.dd64` 文件复制到 x64dbg 的 `db/` 目录，打开目标程序时自动加载标签
2. **脚本加载**：在 x64dbg 中 `Script -> Run Script...` 选择生成的 `.txt` 脚本文件

### Cheat Engine 符号导入

`scripts/ce_symbol_loader.lua` 在 Cheat Engine 中加载符号并注册为可搜索的符号名。

**使用方法：**
1. 在 CE 中附加到目标进程
2. 打开 Lua 引擎：`Memory View -> Tools -> Lua Engine`
3. 加载脚本：
   ```lua
   dofile("E:/Project/TheGreatAI/SymbolDumper/scripts/ce_symbol_loader.lua")
   loadSymbolDumperSymbols()  -- 弹出文件选择对话框
   ```
4. 或直接指定路径：
   ```lua
   dofile("E:/Project/TheGreatAI/SymbolDumper/scripts/ce_symbol_loader.lua")
   loadSymbolDumperSymbols("output/symbols.json", "output/modules.json")
   ```
5. 可选：将符号添加到地址列表：
   ```lua
   addSymbolsToAddressList("output/symbols.json", "output/modules.json", "target.exe", 500)
   ```

## 项目结构

```
SymbolDumper/
  xmake.lua                          # 构建配置
  src/
    main.cpp                          # CLI 入口、DumpOptions、过滤逻辑
    core/
      types.h                         # ModuleInfo, SymbolInfo, FileData
      json_writer.h                   # JSON 序列化
    parser/
      binary_parser.h                 # 格式检测、统一解析接口、去重
      pe_parser.h / pe_parser.cpp     # PE 格式解析
      elf_parser.h / elf_parser.cpp   # ELF 格式解析
      macho_parser.h / macho_parser.cpp # Mach-O 格式解析
    platform/
      process_enum.h                  # 进程枚举接口
      process_enum_win.cpp            # Windows 实现
      process_enum_linux.cpp          # Linux/Android 实现
      process_enum_darwin.cpp         # macOS/iOS 实现
  scripts/
    ida_symbol_resolver.py            # IDA Python 脚本
  tests/
    test_all.ps1                      # PowerShell 测试套件（50 项测试）
```

## 平台支持

| 平台 | 进程枚举 | 符号解析 |
|------|----------|----------|
| Windows | EnumProcessModulesEx | PE 导入/导出/PDB |
| Linux/Android | /proc/pid/maps | ELF symtab/dynsym/dynamic |
| macOS/iOS | task_for_pid / proc_regionfilename | Mach-O symtab/export trie/bind |

> **注意**：Android 需要 root 权限读取 `/proc/<pid>/maps`；iOS 需要 jailbreak 或开发者权限使用 `task_for_pid`。

## 测试

```bash
# Windows 上运行测试套件
powershell -ExecutionPolicy Bypass -File tests/test_all.ps1
```

测试覆盖：帮助输出、进程列表、名称过滤、文件解析、符号过滤（exports/imports/all）、进程 dump、地址计算验证、错误处理。

## 依赖

- **xmake** >= 2.5
- **nlohmann_json**（通过 xmake 自动下载）
- **C++17** 编译器
