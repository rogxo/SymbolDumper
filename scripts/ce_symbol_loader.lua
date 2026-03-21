--[[
  Cheat Engine Symbol Loader Script
  ===================================
  Loads SymbolDumper's symbols.json and registers symbols in Cheat Engine.
  
  Usage in Cheat Engine:
    1. Attach to the target process
    2. Table -> Show Cheat Table Lua Script (Ctrl+Alt+L)
    3. Paste this script or load it via: dofile("path/to/ce_symbol_loader.lua")
    4. Or: Use Lua Engine (Memory View -> Tools -> Lua Engine)
  
  Configuration:
    Set the paths below to your symbols.json and modules.json files.
    Or call loadSymbolDumperSymbols("path/to/symbols.json", "path/to/modules.json")
]]

-- ============================================================
-- Configuration - Edit these paths
-- ============================================================
local DEFAULT_SYMBOLS_PATH = nil  -- Set to your symbols.json path, or nil for dialog
local DEFAULT_MODULES_PATH = nil  -- Set to your modules.json path, or nil for dialog

-- ============================================================
-- JSON Parser (minimal, self-contained)
-- ============================================================
local json = {}

local function skip_whitespace(s, pos)
  local p = pos
  while p <= #s do
    local c = s:byte(p)
    if c == 32 or c == 9 or c == 10 or c == 13 then
      p = p + 1
    else
      break
    end
  end
  return p
end

local function parse_string(s, pos)
  -- pos should be at the opening quote
  local start = pos + 1
  local result = {}
  local i = start
  while i <= #s do
    local c = s:sub(i, i)
    if c == '"' then
      return table.concat(result), i + 1
    elseif c == '\\' then
      i = i + 1
      local esc = s:sub(i, i)
      if esc == '"' then table.insert(result, '"')
      elseif esc == '\\' then table.insert(result, '\\')
      elseif esc == '/' then table.insert(result, '/')
      elseif esc == 'n' then table.insert(result, '\n')
      elseif esc == 'r' then table.insert(result, '\r')
      elseif esc == 't' then table.insert(result, '\t')
      elseif esc == 'b' then table.insert(result, '\b')
      elseif esc == 'f' then table.insert(result, '\f')
      elseif esc == 'u' then
        -- Unicode escape: just store as-is for simplicity
        local hex = s:sub(i+1, i+4)
        local code = tonumber(hex, 16)
        if code and code < 128 then
          table.insert(result, string.char(code))
        else
          table.insert(result, '?')
        end
        i = i + 4
      else
        table.insert(result, esc)
      end
    else
      table.insert(result, c)
    end
    i = i + 1
  end
  error("Unterminated string at position " .. pos)
end

local parse_value -- forward declaration

local function parse_array(s, pos)
  -- pos should be at '['
  local arr = {}
  pos = skip_whitespace(s, pos + 1)
  if s:sub(pos, pos) == ']' then
    return arr, pos + 1
  end
  while true do
    local val
    val, pos = parse_value(s, pos)
    table.insert(arr, val)
    pos = skip_whitespace(s, pos)
    local c = s:sub(pos, pos)
    if c == ']' then
      return arr, pos + 1
    elseif c == ',' then
      pos = skip_whitespace(s, pos + 1)
    else
      error("Expected ',' or ']' at position " .. pos)
    end
  end
end

local function parse_object(s, pos)
  -- pos should be at '{'
  local obj = {}
  pos = skip_whitespace(s, pos + 1)
  if s:sub(pos, pos) == '}' then
    return obj, pos + 1
  end
  while true do
    -- key
    pos = skip_whitespace(s, pos)
    if s:sub(pos, pos) ~= '"' then
      error("Expected string key at position " .. pos)
    end
    local key
    key, pos = parse_string(s, pos)
    pos = skip_whitespace(s, pos)
    if s:sub(pos, pos) ~= ':' then
      error("Expected ':' at position " .. pos)
    end
    pos = skip_whitespace(s, pos + 1)
    local val
    val, pos = parse_value(s, pos)
    obj[key] = val
    pos = skip_whitespace(s, pos)
    local c = s:sub(pos, pos)
    if c == '}' then
      return obj, pos + 1
    elseif c == ',' then
      pos = skip_whitespace(s, pos + 1)
    else
      error("Expected ',' or '}' at position " .. pos .. " got '" .. c .. "'")
    end
  end
end

local function parse_number(s, pos)
  local start = pos
  if s:sub(pos, pos) == '-' then pos = pos + 1 end
  while pos <= #s and s:sub(pos, pos):match('[%d]') do pos = pos + 1 end
  if pos <= #s and s:sub(pos, pos) == '.' then
    pos = pos + 1
    while pos <= #s and s:sub(pos, pos):match('[%d]') do pos = pos + 1 end
  end
  if pos <= #s and s:sub(pos, pos):lower() == 'e' then
    pos = pos + 1
    if pos <= #s and (s:sub(pos, pos) == '+' or s:sub(pos, pos) == '-') then
      pos = pos + 1
    end
    while pos <= #s and s:sub(pos, pos):match('[%d]') do pos = pos + 1 end
  end
  return tonumber(s:sub(start, pos - 1)), pos
end

parse_value = function(s, pos)
  pos = skip_whitespace(s, pos)
  local c = s:sub(pos, pos)
  if c == '"' then return parse_string(s, pos)
  elseif c == '{' then return parse_object(s, pos)
  elseif c == '[' then return parse_array(s, pos)
  elseif c == 't' then
    if s:sub(pos, pos + 3) == 'true' then return true, pos + 4 end
  elseif c == 'f' then
    if s:sub(pos, pos + 4) == 'false' then return false, pos + 5 end
  elseif c == 'n' then
    if s:sub(pos, pos + 3) == 'null' then return nil, pos + 4 end
  elseif c == '-' or c:match('[%d]') then
    return parse_number(s, pos)
  end
  error("Unexpected character '" .. c .. "' at position " .. pos)
end

function json.decode(s)
  local val, pos = parse_value(s, 1)
  return val
end

-- ============================================================
-- Utility Functions
-- ============================================================

local function parseHex(val)
  if type(val) == "number" then return val end
  if type(val) == "string" then
    val = val:gsub("^0[xX]", "")
    return tonumber(val, 16) or 0
  end
  return 0
end

local function readFile(path)
  local f = io.open(path, "r")
  if not f then
    print("[SymbolDumper] ERROR: Cannot open file: " .. path)
    return nil
  end
  local content = f:read("*a")
  f:close()
  return content
end

local function fileDialog(title, filter)
  -- Use CE's built-in file dialog
  local dialog = createOpenDialog(nil)
  if dialog then
    dialog.Title = title or "Select file"
    dialog.Filter = filter or "JSON files (*.json)|*.json|All files (*.*)|*.*"
    dialog.FilterIndex = 0
    if dialog.Execute() then
      local path = dialog.FileName
      dialog.destroy()
      return path
    end
    dialog.destroy()
  end
  return nil
end

-- ============================================================
-- Symbol Loading
-- ============================================================

local function getModuleBaseByName(moduleName)
  -- Try to get the base address of a module in the current process
  local result = getAddress(moduleName)
  if result and result ~= 0 then
    return result
  end
  -- Try enumeration
  if enumModules then
    local modules = enumModules()
    if modules then
      local lowerName = moduleName:lower()
      for i, mod in ipairs(modules) do
        if mod.Name:lower() == lowerName then
          return mod.Address
        end
        -- Also try partial match
        if mod.Name:lower():find(lowerName, 1, true) then
          return mod.Address
        end
      end
    end
  end
  return nil
end

function loadSymbolDumperSymbols(symbolsPath, modulesPath)
  print("============================================================")
  print("  SymbolDumper - Cheat Engine Symbol Loader")
  print("============================================================")

  -- Load symbols JSON
  if not symbolsPath then
    symbolsPath = fileDialog("Select symbols.json")
  end
  if not symbolsPath then
    print("[SymbolDumper] No symbols.json selected. Aborting.")
    return
  end

  print("[SymbolDumper] Loading: " .. symbolsPath)
  local symbolsContent = readFile(symbolsPath)
  if not symbolsContent then return end

  print("[SymbolDumper] Parsing JSON (" .. #symbolsContent .. " bytes)...")
  local ok, symbolsData = pcall(json.decode, symbolsContent)
  if not ok then
    print("[SymbolDumper] ERROR: Failed to parse symbols.json: " .. tostring(symbolsData))
    return
  end
  symbolsContent = nil -- Free memory
  collectgarbage()

  -- Load modules JSON (optional, for base address info)
  local modulesData = nil
  if modulesPath then
    local modulesContent = readFile(modulesPath)
    if modulesContent then
      ok, modulesData = pcall(json.decode, modulesContent)
      if not ok then
        print("[SymbolDumper] WARNING: Failed to parse modules.json, continuing without it")
        modulesData = nil
      end
    end
  end

  -- Process info
  local processName = "unknown"
  local processPid = 0
  if modulesData then
    processName = modulesData.process_name or "unknown"
    processPid = modulesData.process_id or 0
    print(string.format("[SymbolDumper] Target process: %s (PID: %d)", processName, processPid))
  end

  -- Register symbols
  local modules = symbolsData.modules or {}
  local totalRegistered = 0
  local totalSkipped = 0
  local totalModules = #modules

  print(string.format("[SymbolDumper] Processing %d modules...", totalModules))

  for i, modSym in ipairs(modules) do
    local moduleName = modSym.module_name or ""
    local jsonBase = parseHex(modSym.base_address or "0")
    local symbols = modSym.symbols or {}

    -- Try to find the actual base address of this module in the current process
    local actualBase = getModuleBaseByName(moduleName)

    if actualBase then
      print(string.format("[SymbolDumper] Module: %s (base: 0x%X, json_base: 0x%X, symbols: %d)",
        moduleName, actualBase, jsonBase, #symbols))

      local moduleRegistered = 0
      for _, sym in ipairs(symbols) do
        local name = sym.name or ""
        local rva = parseHex(sym.rva or "0")

        if name ~= "" and rva ~= 0 then
          local addr = actualBase + rva

          -- Register the symbol with CE using registerSymbol
          -- This allows using the symbol name in CE's address bar
          local safeName = name:gsub("[^%w_%.%$]", "_")
          if safeName:match("^%d") then
            safeName = "_" .. safeName
          end

          -- Use module-qualified name to avoid conflicts
          local qualifiedName = moduleName:gsub("%.[^%.]+$", "") .. "!" .. safeName

          -- Register both simple and qualified names
          local success = pcall(function()
            registerSymbol(qualifiedName, addr, true)
          end)
          if success then
            moduleRegistered = moduleRegistered + 1
            totalRegistered = totalRegistered + 1
          else
            totalSkipped = totalSkipped + 1
          end
        end
      end

      print(string.format("  -> Registered %d symbols", moduleRegistered))
    else
      print(string.format("[SymbolDumper] Module not found in process: %s (skipping %d symbols)",
        moduleName, #symbols))
      totalSkipped = totalSkipped + #symbols
    end
  end

  print("")
  print("============================================================")
  print(string.format("  Done! Registered: %d, Skipped: %d", totalRegistered, totalSkipped))
  print("  Symbols can now be used in CE's address bar.")
  print("  Example: Type a symbol name in 'Add Address Manually'")
  print("============================================================")

  return totalRegistered
end

-- ============================================================
-- Address List Helper
-- ============================================================

function addSymbolsToAddressList(symbolsPath, modulesPath, filterModule, maxEntries)
  --[[
    Add symbols to CE's address list (the main cheat table).
    filterModule: only add symbols from this module (nil = all)
    maxEntries: limit number of entries (default 1000)
  ]]
  maxEntries = maxEntries or 1000

  if not symbolsPath then
    symbolsPath = fileDialog("Select symbols.json")
  end
  if not symbolsPath then return end

  local content = readFile(symbolsPath)
  if not content then return end

  local ok, data = pcall(json.decode, content)
  if not ok then
    print("[SymbolDumper] ERROR: JSON parse failed")
    return
  end
  content = nil
  collectgarbage()

  local addressList = getAddressList()
  local count = 0

  for _, modSym in ipairs(data.modules or {}) do
    local moduleName = modSym.module_name or ""
    if filterModule and moduleName:lower() ~= filterModule:lower() then
      goto continue_mod
    end

    local actualBase = getModuleBaseByName(moduleName)
    if not actualBase then
      goto continue_mod
    end

    for _, sym in ipairs(modSym.symbols or {}) do
      if count >= maxEntries then
        print(string.format("[SymbolDumper] Reached max entries limit (%d)", maxEntries))
        goto done
      end

      local name = sym.name or ""
      local rva = parseHex(sym.rva or "0")
      local symType = sym.type or ""

      if name ~= "" and rva ~= 0 then
        local addr = actualBase + rva
        local entry = addressList.createMemoryRecord()
        entry.Description = string.format("%s!%s", moduleName, name)
        entry.Address = string.format("%X", addr)

        -- Set value type based on symbol type
        if symType == "function" then
          entry.Type = vtByteArray
          entry.Aob.Size = 16  -- Show first 16 bytes
        else
          entry.Type = vtQword  -- Default to 8-byte value
        end

        count = count + 1
      end
    end

    ::continue_mod::
  end

  ::done::
  print(string.format("[SymbolDumper] Added %d entries to address list", count))
  return count
end

-- ============================================================
-- Auto-run on load
-- ============================================================

-- Check if we have a process attached
if getOpenedProcessID() ~= 0 then
  print("[SymbolDumper] Process attached (PID: " .. getOpenedProcessID() .. ")")
  print("[SymbolDumper] Call loadSymbolDumperSymbols() to load symbols")
  print("[SymbolDumper] Call addSymbolsToAddressList() to add to address list")
  print("")
  print("Quick start:")
  print('  loadSymbolDumperSymbols("path/to/symbols.json", "path/to/modules.json")')
  print('  loadSymbolDumperSymbols()  -- will show file dialog')
else
  print("[SymbolDumper] No process attached. Attach to a process first,")
  print("then call loadSymbolDumperSymbols()")
end
