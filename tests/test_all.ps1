# SymbolDumper Test Suite (PowerShell)
# Run: powershell -ExecutionPolicy Bypass -File tests\test_all.ps1

$ErrorActionPreference = "Continue"
$script:passed = 0
$script:failed = 0
$script:total  = 0

$exe = "e:\Project\TheGreatAI\SymbolDumper\build\windows\x64\release\symbol_dumper.exe"
$testDir = "e:\Project\TheGreatAI\SymbolDumper\tests\test_output"

function Assert-True($condition, $msg) {
    $script:total++
    if ($condition) {
        Write-Host "  [PASS] $msg" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "  [FAIL] $msg" -ForegroundColor Red
        $script:failed++
    }
}

function Cleanup {
    if (Test-Path $testDir) { Remove-Item -Recurse -Force $testDir }
}

# ============================================================
Write-Host "`n=== Test 1: --help ===" -ForegroundColor Cyan
$out = & $exe --help 2>&1 | Out-String
Assert-True ($out -match "SymbolDumper") "Help shows tool name"
Assert-True ($out -match "--pid") "Help shows --pid"
Assert-True ($out -match "--name") "Help shows --name"
Assert-True ($out -match "--exports") "Help shows --exports"
Assert-True ($out -match "--all") "Help shows --all"

# ============================================================
Write-Host "`n=== Test 2: --list ===" -ForegroundColor Cyan
$out = & $exe --list 2>&1 | Out-String
Assert-True ($out -match "PID\s+Name") "Process list header"
Assert-True ($out -match "Total:") "Process list total count"
Assert-True ($out -match "svchost") "Known process svchost in list"

# ============================================================
Write-Host "`n=== Test 3: --list with --name filter ===" -ForegroundColor Cyan
$out = & $exe --list -n explorer 2>&1 | Out-String
Assert-True ($out -match "Explorer") "Name filter finds explorer"
Assert-True ($out -match "Matched:") "Shows matched count"

# ============================================================
Write-Host "`n=== Test 4: --file default (exports+imports) ===" -ForegroundColor Cyan
Cleanup
$out = & $exe -f "C:\Windows\System32\kernel32.dll" -o "$testDir\t4" 2>&1 | Out-String
Assert-True ($out -match "exports\+imports") "Default filter is exports+imports"
Assert-True ($out -match "Image base: 0x180000000") "PE ImageBase extracted correctly"
Assert-True ($out -match "PDB path: kernel32.pdb") "PDB path found"
Assert-True (Test-Path "$testDir\t4\kernel32_modules.json") "modules.json created"
Assert-True (Test-Path "$testDir\t4\kernel32_symbols.json") "symbols.json created"

# Verify JSON content
$mods = Get-Content "$testDir\t4\kernel32_modules.json" | ConvertFrom-Json
Assert-True ($mods.modules[0].base_address -eq "0x180000000") "modules.json has correct base_address"

$syms = Get-Content "$testDir\t4\kernel32_symbols.json" | ConvertFrom-Json
$symList = $syms.modules[0].symbols
Assert-True ($syms.modules[0].symbol_count -eq $symList.Count) "symbol_count matches array length"

$exports = $symList | Where-Object { $_.source -eq "export_table" }
$imports = $symList | Where-Object { $_.source -eq "import_table" }
Assert-True ($exports.Count -eq 1634) "Export count = 1634"
Assert-True ($imports.Count -eq 1262) "Import count = 1262"

# Verify specific symbol addresses
$actCtx = $symList | Where-Object { $_.name -eq "ActivateActCtx" -and $_.source -eq "export_table" }
Assert-True ($actCtx.rva -eq "0x203C0") "ActivateActCtx RVA correct"
Assert-True ($actCtx.address -eq "0x1800203C0") "ActivateActCtx address = base+rva"

# Verify forwarder
$fwd = $symList | Where-Object { $_.name -eq "AcquireSRWLockExclusive" }
Assert-True ($fwd.type -eq "forwarder") "AcquireSRWLockExclusive is forwarder"
Assert-True ($fwd.library -match "NTDLL") "Forwarder points to NTDLL"

# ============================================================
Write-Host "`n=== Test 5: --file --exports only ===" -ForegroundColor Cyan
$out = & $exe -f "C:\Windows\System32\kernel32.dll" -E -o "$testDir\t5" 2>&1 | Out-String
Assert-True ($out -match "Symbol filter: exports") "Filter shows exports"
Assert-True ($out -match "1634 \(filtered from 2896\)") "Filtered to 1634 exports"

$syms5 = Get-Content "$testDir\t5\kernel32_symbols.json" | ConvertFrom-Json
$imp5 = $syms5.modules[0].symbols | Where-Object { $_.source -eq "import_table" }
Assert-True ($imp5.Count -eq 0) "No imports in exports-only output"

# ============================================================
Write-Host "`n=== Test 6: --file --imports only ===" -ForegroundColor Cyan
$out = & $exe -f "C:\Windows\System32\kernel32.dll" -I -o "$testDir\t6" 2>&1 | Out-String
Assert-True ($out -match "Symbol filter: imports") "Filter shows imports"
Assert-True ($out -match "1262 \(filtered from 2896\)") "Filtered to 1262 imports"

# ============================================================
Write-Host "`n=== Test 7: --file --all ===" -ForegroundColor Cyan
$out = & $exe -f "C:\Windows\System32\kernel32.dll" -A -o "$testDir\t7" 2>&1 | Out-String
Assert-True ($out -match "Symbol filter: all") "Filter shows all"
Assert-True ($out -match "2896 \(filtered from 2896\)") "All symbols included"

# ============================================================
Write-Host "`n=== Test 8: --file --libs ===" -ForegroundColor Cyan
$out = & $exe -f "C:\Windows\System32\kernel32.dll" --libs -o "$testDir\t8" 2>&1 | Out-String
# PE imports come from import table, --libs shows imported DLLs for ELF/Mach-O
# For PE, imported_libs list is empty (import DLLs are embedded in import symbols)
Assert-True ($LASTEXITCODE -eq 0) "--libs flag accepted"

# ============================================================
Write-Host "`n=== Test 9: --name process dump ===" -ForegroundColor Cyan
$out = & $exe --name explorer -o "$testDir\t9" 2>&1 | Out-String
Assert-True ($out -match "Process: Explorer") "Found explorer by name"
Assert-True ($out -match "modules") "Module count shown"
Assert-True (Test-Path "$testDir\t9\modules.json") "Process modules.json created"
Assert-True (Test-Path "$testDir\t9\symbols.json") "Process symbols.json created"

# Verify process JSON
$procMods = Get-Content "$testDir\t9\modules.json" | ConvertFrom-Json
Assert-True ($procMods.process_id -gt 0) "Process ID is non-zero"
Assert-True ($procMods.modules.Count -gt 50) "Many modules loaded (>50)"

$procSyms = Get-Content "$testDir\t9\symbols.json" | ConvertFrom-Json
$k32mod = $procSyms.modules | Where-Object { $_.module_name -eq "KERNEL32.DLL" }
Assert-True ($null -ne $k32mod) "KERNEL32.DLL found in symbols"
Assert-True ($k32mod.base_address -match "0x7FF") "KERNEL32 has runtime base (0x7FF...)"

$k32act = $k32mod.symbols | Where-Object { $_.name -eq "ActivateActCtx" -and $_.source -eq "export_table" }
Assert-True ($null -ne $k32act) "ActivateActCtx found in process dump"
# Verify address = base + rva
$base = [Convert]::ToUInt64($k32mod.base_address.Replace("0x",""), 16)
$rva  = [Convert]::ToUInt64($k32act.rva.Replace("0x",""), 16)
$addr = [Convert]::ToUInt64($k32act.address.Replace("0x",""), 16)
Assert-True ($addr -eq ($base + $rva)) "Process symbol address = base + rva"

# ============================================================
Write-Host "`n=== Test 10: --name with --all -v ===" -ForegroundColor Cyan
$out = & $exe --name explorer --all -v -o "$testDir\t10" 2>&1 | Out-String
Assert-True ($out -match "Symbol filter: all") "All filter with verbose"
Assert-True ($out -match "Parsing:") "Verbose shows per-module parsing"
Assert-True ($out -match "PDB:") "Verbose shows PDB info"

# ============================================================
Write-Host "`n=== Test 11: Parse ntdll.dll ===" -ForegroundColor Cyan
$out = & $exe -f "C:\Windows\System32\ntdll.dll" -A -o "$testDir\t11" 2>&1 | Out-String
Assert-True ($out -match "PE \(64-bit\)") "ntdll.dll detected as PE 64-bit"
$ntdllSyms = Get-Content "$testDir\t11\ntdll_symbols.json" | ConvertFrom-Json
$ntdllExp = $ntdllSyms.modules[0].symbols | Where-Object { $_.source -eq "export_table" -and $_.name -eq "NtCreateFile" }
Assert-True ($null -ne $ntdllExp) "NtCreateFile found in ntdll exports"

# ============================================================
Write-Host "`n=== Test 12: Error handling - nonexistent file ===" -ForegroundColor Cyan
$out = & $exe -f "C:\nonexistent.dll" -o "$testDir\t12" 2>&1 | Out-String
$ec12 = $LASTEXITCODE
Assert-True ($out -match "Failed") "Error message for nonexistent file"
Assert-True ($ec12 -ne 0 -or $out -match "Failed") "Non-zero exit or error msg for bad file"

# ============================================================
Write-Host "`n=== Test 13: Error handling - invalid PID ===" -ForegroundColor Cyan
$out = & $exe -p 99999999 -o "$testDir\t13" 2>&1 | Out-String
$ec13 = $LASTEXITCODE
Assert-True ($out -match "Failed") "Error message for invalid PID"
Assert-True ($ec13 -ne 0 -or $out -match "Failed") "Non-zero exit or error msg for bad PID"

# ============================================================
# Summary
Cleanup
Write-Host "`n============================================" -ForegroundColor Yellow
Write-Host "  Test Results: $script:passed/$script:total passed, $script:failed failed" -ForegroundColor $(if ($script:failed -eq 0) { "Green" } else { "Red" })
Write-Host "============================================`n" -ForegroundColor Yellow

exit $script:failed
