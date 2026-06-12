local M = {}

local vault = require("ansible-vault")
local health = vim.health

local function is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

local function expand_path(path)
  return vim.fn.expand(path)
end

local function path_exists(path)
  return vim.fn.filereadable(path) == 1 or vim.fn.isdirectory(path) == 1
end

local function check_password_file(path, label)
  local expanded = expand_path(path)
  if vim.fn.filereadable(expanded) ~= 1 then
    health.error(string.format("%s is not readable: %s", label, expanded))
    return
  end

  local perm = vim.fn.getfperm(expanded)
  if perm:sub(4) ~= "------" then
    health.warn(string.format("%s is readable by group/other: %s (%s)", label, expanded, perm))
    return
  end

  health.ok(string.format("%s is readable with restrictive permissions: %s", label, expanded))
end

local function parse_vault_label(vault_id)
  return vault_id:match("^([^@]+)@")
end

local function collect_vault_ids(config)
  local result = {}

  if type(config.vault_ids) == "table" and #config.vault_ids > 0 then
    for _, vault_id in ipairs(config.vault_ids) do
      if is_nonempty_string(vault_id) then
        table.insert(result, vault_id)
      end
    end
  elseif is_nonempty_string(config.vault_id) then
    table.insert(result, config.vault_id)
  end

  return result
end

local function check_vault_ids(config)
  local vault_ids = collect_vault_ids(config)
  if #vault_ids == 0 then
    return
  end

  local labels = {}
  for _, vault_id in ipairs(vault_ids) do
    local label = parse_vault_label(vault_id)
    if label then
      labels[label] = true
    end

    local source = vault_id:match("^[^@]+@(.+)$")
    if source and source ~= "prompt" and not path_exists(expand_path(source)) then
      health.warn(string.format("vault_id source is not readable: %s", expand_path(source)))
    end
  end

  health.info(string.format("Configured vault IDs: %d", #vault_ids))

  if #vault_ids > 1 and not is_nonempty_string(config.encrypt_vault_id) then
    health.warn("Multiple vault_ids are configured; set encrypt_vault_id for deterministic encryption")
  end

  if is_nonempty_string(config.encrypt_vault_id) and next(labels) ~= nil and not labels[config.encrypt_vault_id] then
    health.warn(
      string.format("encrypt_vault_id '%s' does not match configured vault_id labels", config.encrypt_vault_id)
    )
  end
end

function M.check()
  local legacy = vim.fn.has("nvim-0.10") == 0
  if legacy then
    health = {
      ok = function(msg)
        print("  - OK: " .. msg)
      end,
      warn = function(msg)
        print("  - WARN: " .. msg)
      end,
      error = function(msg)
        print("  - ERROR: " .. msg)
      end,
      info = function(msg)
        print("  - INFO: " .. msg)
      end,
    }
    print("ansible-vault.nvim health check:")
  else
    health.start("ansible-vault.nvim")
  end

  local argv = vault._private.get_vault_argv()
  local executable = argv[1]
  if executable == "conda" then
    if vim.fn.executable("conda") == 1 then
      health.ok("conda executable found")
    else
      health.error("conda executable not found")
    end
    health.info("ansible-vault will run through: " .. table.concat(argv, " "))
  elseif vim.fn.executable(executable) == 1 then
    health.ok("ansible-vault executable found: " .. executable)
  else
    health.error("ansible-vault executable not found: " .. executable)
  end

  local config = vault.config
  if is_nonempty_string(config.password_file) then
    check_password_file(config.password_file, "password_file")
    if is_nonempty_string(config.vault_id) or (type(config.vault_ids) == "table" and #config.vault_ids > 0) then
      health.info("password_file takes precedence over vault_id/vault_ids")
    end
  else
    check_vault_ids(config)
    if
      not is_nonempty_string(config.vault_id) and not (type(config.vault_ids) == "table" and #config.vault_ids > 0)
    then
      health.warn("No password_file or vault_id configured; commands will prompt for a password")
    end
  end

  if is_nonempty_string(config.rekey_password_file) then
    check_password_file(config.rekey_password_file, "rekey_password_file")
  elseif is_nonempty_string(config.rekey_vault_id) then
    health.info("VaultRekey new vault ID configured: " .. config.rekey_vault_id)
  else
    health.info("VaultRekey requires --new-vault-* command args when no rekey target is configured")
  end
end

return M
