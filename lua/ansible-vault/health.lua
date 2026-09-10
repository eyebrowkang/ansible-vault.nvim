local M = {}

local credentials = require("ansible-vault.credentials")
local secure = require("ansible-vault.secure")
local vault = require("ansible-vault")
local health = vim.health

local function is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

local expand_path = credentials.expand_path

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

  -- Ansible runs an executable password file and takes its stdout as the
  -- password, so the execute bit is a supported configuration, not a mistake.
  if vim.fn.executable(expanded) == 1 then
    if perm:sub(4) ~= "------" then
      health.warn(string.format("%s is an executable script readable by group/other: %s (%s)", label, expanded, perm))
    else
      health.ok(string.format("%s is an executable password script: %s", label, expanded))
    end
    return
  end

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

  -- Resolved through the same code path the real operations use, so this cannot
  -- report a credential source that is not the one in effect.
  local resolved = credentials.describe(config, { file_path = vim.api.nvim_buf_get_name(0) })

  health.info("Credential source: " .. resolved.source)
  if resolved.cfg_path then
    health.info(string.format("ansible.cfg: %s (found via %s)", resolved.cfg_path, resolved.cfg_source))
    health.info("ansible-vault will run in: " .. (resolved.cwd or "the current directory"))
  else
    health.info("No ansible.cfg found")
  end

  if resolved.needs_disambiguation then
    health.info(
      string.format(
        "Ansible's own config supplies a second identity; encryption will name '%s' explicitly",
        resolved.encrypt_label or "default"
      )
    )
  end

  if is_nonempty_string(config.password_file) then
    check_password_file(config.password_file, "password_file")
    if is_nonempty_string(config.vault_id) or (type(config.vault_ids) == "table" and #config.vault_ids > 0) then
      health.info("password_file takes precedence over vault_id/vault_ids")
    end
  else
    check_vault_ids(config)
    if resolved.source == "interactive" then
      health.warn("No password_file, vault_id, ANSIBLE_* variable or ansible.cfg found; commands will prompt")
    end
  end

  if is_nonempty_string(config.rekey_password_file) then
    check_password_file(config.rekey_password_file, "rekey_password_file")
  elseif is_nonempty_string(config.rekey_vault_id) then
    health.info("VaultRekey new vault ID configured: " .. config.rekey_vault_id)
  else
    health.info("VaultRekey requires --new-vault-* command args when no rekey target is configured")
  end

  -- Global options the plugin deliberately leaves alone.
  local warnings = secure.global_warnings()
  if #warnings == 0 then
    health.ok("No global options that could persist decrypted content are enabled")
  else
    for _, warning in ipairs(warnings) do
      health.warn(warning)
    end
  end

  local askpass, askpass_err = credentials._private.ensure_askpass()
  if askpass then
    health.ok("Interactive passwords are passed via the environment; nothing secret is written to disk")
  else
    health.warn(
      "Falling back to a 0600 temporary password file ("
        .. (askpass_err or "unknown reason")
        .. "); it is removed on exit but would survive a crash"
    )
  end
end

return M
