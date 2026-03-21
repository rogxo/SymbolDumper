"""
x64dbg Symbol Loader Script
================================
Converts SymbolDumper's symbols.json / modules.json into x64dbg-compatible
database files (.dd32 / .dd64) that can be loaded automatically.

Usage:
  python x64dbg_symbol_loader.py [options]

Options:
  --symbols <path>    Path to symbols.json (default: ./output/symbols.json)
  --modules <path>    Path to modules.json (default: ./output/modules.json)
  --output  <dir>     Output directory for .dd64 files (default: ./output/x64dbg)
  --dbdir   <dir>     x64dbg db/ directory (auto-copy generated files there)
  --bits    <32|64>   Force 32 or 64 bit mode (default: auto-detect)
  --script            Also generate an x64dbg script (.txt) with lbl commands

The generated .dd64/.dd32 file should be placed in x64dbg's db/ directory,
named as "<executable_name>.dd64" (e.g. "target.exe.dd64").
When x64dbg opens that executable, it will auto-load the labels.

Alternatively, use --script to produce a .txt command script that can be
executed inside x64dbg via: Script -> Run Script...
"""

import json
import os
import sys
import argparse
import shutil
from pathlib import Path


def parse_hex(val):
    """Parse a hex string like '0x1234' to int."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        return int(val, 16)
    return 0


def sanitize_label(name):
    """
    Sanitize a symbol name for x64dbg labels.
    x64dbg labels support most characters, but we strip problematic ones.
    """
    # x64dbg is fairly permissive with label names
    # Just remove null bytes and control characters
    result = []
    for ch in name:
        if ord(ch) < 32:
            continue
        result.append(ch)
    s = ''.join(result).strip()
    # Limit length
    if len(s) > 255:
        s = s[:255]
    return s


def load_json(path):
    """Load and parse a JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def detect_bitness(modules_data, symbols_data):
    """Auto-detect 32/64 bit based on address sizes."""
    for mod in modules_data.get("modules", []):
        addr = parse_hex(mod.get("base_address", "0"))
        if addr > 0xFFFFFFFF:
            return 64
    for mod_syms in symbols_data.get("modules", []):
        for sym in mod_syms.get("symbols", [])[:10]:
            addr = parse_hex(sym.get("address", "0"))
            if addr > 0xFFFFFFFF:
                return 64
    return 32


def generate_x64dbg_database(symbols_data, modules_data, bitness):
    """
    Generate an x64dbg database dict with labels and comments.

    x64dbg database format:
    {
      "labels": [
        {"module": "mod.dll", "address": "0xRVA", "manual": true, "text": "name"}
      ],
      "comments": [
        {"module": "mod.dll", "address": "0xRVA", "manual": true, "text": "comment"}
      ],
      "bookmarks": []
    }

    When "module" is specified, "address" is treated as RVA from module base.
    """
    labels = []
    comments = []

    total = 0
    for mod_syms in symbols_data.get("modules", []):
        module_name = mod_syms.get("module_name", "")
        base_addr = parse_hex(mod_syms.get("base_address", "0"))
        symbols = mod_syms.get("symbols", [])

        seen_rvas = set()  # Deduplicate within each module

        for sym in symbols:
            name = sym.get("name", "")
            if not name:
                continue

            rva = parse_hex(sym.get("rva", "0"))
            if rva == 0:
                continue

            # Deduplicate: keep first symbol per RVA per module
            if rva in seen_rvas:
                continue
            seen_rvas.add(rva)

            label_text = sanitize_label(name)
            if not label_text:
                continue

            # Format address as hex string
            rva_hex = f"0x{rva:X}"

            labels.append({
                "module": module_name,
                "address": rva_hex,
                "manual": True,
                "text": label_text
            })

            # Add source info as comment
            sym_type = sym.get("type", "")
            source = sym.get("source", "")
            library = sym.get("library", "")

            comment_parts = [f"[SD] {source}"]
            if sym_type:
                comment_parts.append(sym_type)
            if library:
                comment_parts.append(f"from {library}")

            comments.append({
                "module": module_name,
                "address": rva_hex,
                "manual": True,
                "text": " | ".join(comment_parts)
            })

            total += 1

    db = {
        "labels": labels,
        "comments": comments,
        "bookmarks": [],
        "breakpoints": []
    }

    return db, total


def generate_x64dbg_script(symbols_data, modules_data, bitness):
    """
    Generate an x64dbg command script (.txt) with lbl/cmt commands.
    Format: lbl <module>.rva, "name"
    """
    lines = [
        "; SymbolDumper - x64dbg Symbol Import Script",
        "; Generated from symbols.json",
        "; Usage: Script -> Run Script... in x64dbg",
        ";",
        "log \"[SymbolDumper] Starting symbol import...\"",
        ""
    ]

    total = 0
    for mod_syms in symbols_data.get("modules", []):
        module_name = mod_syms.get("module_name", "")
        symbols = mod_syms.get("symbols", [])

        if not symbols:
            continue

        lines.append(f"; Module: {module_name} ({len(symbols)} symbols)")

        seen_rvas = set()
        for sym in symbols:
            name = sym.get("name", "")
            rva = parse_hex(sym.get("rva", "0"))

            if not name or rva == 0 or rva in seen_rvas:
                continue
            seen_rvas.add(rva)

            label = sanitize_label(name)
            if not label:
                continue

            # x64dbg script command: lbl <module_name>:<rva>, "label"
            lines.append(f'lbl {module_name}:{rva:#x}, "{label}"')
            total += 1

    lines.append("")
    lines.append(f'log "[SymbolDumper] Done! {total} labels applied."')
    lines.append("")

    return '\n'.join(lines), total


def main():
    parser = argparse.ArgumentParser(
        description="Convert SymbolDumper output to x64dbg database files"
    )
    parser.add_argument("--symbols", default="./output/symbols.json",
                        help="Path to symbols.json")
    parser.add_argument("--modules", default="./output/modules.json",
                        help="Path to modules.json")
    parser.add_argument("--output", default="./output/x64dbg",
                        help="Output directory")
    parser.add_argument("--dbdir", default=None,
                        help="x64dbg db/ directory (auto-copy files there)")
    parser.add_argument("--bits", type=int, choices=[32, 64], default=None,
                        help="Force 32 or 64 bit mode")
    parser.add_argument("--script", action="store_true",
                        help="Also generate x64dbg command script (.txt)")

    args = parser.parse_args()

    # Load data
    print("[SymbolDumper] Loading symbols...")
    symbols_data = load_json(args.symbols)
    modules_data = load_json(args.modules)

    # Detect bitness
    bitness = args.bits or detect_bitness(modules_data, symbols_data)
    ext = "dd64" if bitness == 64 else "dd32"
    print(f"[SymbolDumper] Bitness: {bitness}-bit (extension: .{ext})")

    # Count modules and symbols
    mod_count = len(symbols_data.get("modules", []))
    sym_count = sum(len(m.get("symbols", [])) for m in symbols_data.get("modules", []))
    print(f"[SymbolDumper] Modules: {mod_count}, Total symbols: {sym_count}")

    # Generate database
    print("[SymbolDumper] Generating x64dbg database...")
    db, label_count = generate_x64dbg_database(symbols_data, modules_data, bitness)
    print(f"[SymbolDumper] Generated {label_count} labels")

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Determine output filename based on the first/main module
    main_module = ""
    modules_list = modules_data.get("modules", [])
    if modules_list:
        main_module = modules_list[0].get("name", "unknown")

    db_filename = f"{main_module}.{ext}"
    db_path = os.path.join(args.output, db_filename)

    # Write database file
    with open(db_path, 'w', encoding='utf-8') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    print(f"[SymbolDumper] Database saved: {db_path}")

    # Optionally generate script
    if args.script:
        script_content, script_count = generate_x64dbg_script(
            symbols_data, modules_data, bitness
        )
        script_path = os.path.join(args.output, f"{main_module}_labels.txt")
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        print(f"[SymbolDumper] Script saved: {script_path} ({script_count} commands)")

    # Optionally copy to x64dbg db directory
    if args.dbdir:
        dest = os.path.join(args.dbdir, db_filename)
        shutil.copy2(db_path, dest)
        print(f"[SymbolDumper] Copied to x64dbg db: {dest}")

    print()
    print("=" * 50)
    print("  How to use in x64dbg:")
    print("=" * 50)
    print(f"  1. Copy '{db_filename}' to x64dbg's db/ directory")
    print(f"     (usually: x64dbg/db/{db_filename})")
    print(f"  2. Open the target executable in x64dbg")
    print(f"  3. Labels will be loaded automatically")
    if args.script:
        print(f"  OR: Script -> Run Script -> select the .txt file")
    print()


if __name__ == "__main__":
    main()
