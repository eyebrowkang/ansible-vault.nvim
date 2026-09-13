---`:checkhealth ansible-vault`.
---
---Answers exactly four questions: can this Neovim run the plugin, can it run
---`ansible-vault`, which credential would an operation actually use, and is
---anything in the global configuration able to keep a copy of decrypted content.
---
---Everything is read through the same code the operations use, so the report
---cannot describe a credential source that is not the one in effect. Nothing here
---has side effects: a diagnostic that installs the password helper would be
---reporting on a state it created.
local M = {}

local cli = require("ansible-vault.cli")
local config = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")
local secure = require("ansible-vault.secure")
local health = vim.health

local function is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

local function path_exists(path)
  return vim.fn.filereadable(path) == 1 or vim.fn.isdirectory(path) == 1
end

local function check_password_file(path, label)
  local expanded = credentials.expand_path(path)
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

local function check_vault_ids(values)
  local vault_ids = credentials.as_list(values.vault_ids)
  if #vault_ids == 0 then
    return
  end

  local labels = {}
  for _, vault_id in ipairs(vault_ids) do
    local label = vault_id:match("^([^@]+)@")
    if label then
      labels[label] = true
    end

    -- Both of Ansible's asking sources name a password the user types rather
    -- than a file to read, so neither can be missing from disk.
    local source = vault_id:match("^[^@]+@(.+)$")
    if source and not credentials.is_prompt_source(source) and not path_exists(credentials.expand_path(source)) then
      health.warn(string.format("vault_id source is not readable: %s", credentials.expand_path(source)))
    end
  end

  health.info(string.format("Configured vault IDs: %d", #vault_ids))

  if #vault_ids > 1 and not is_nonempty_string(values.encrypt_vault_id) then
    health.warn("Multiple vault_ids are configured; set encrypt_vault_id for deterministic encryption")
  end

  if is_nonempty_string(values.encrypt_vault_id) and next(labels) ~= nil and not labels[values.encrypt_vault_id] then
    health.warn(
      string.format("encrypt_vault_id '%s' does not match configured vault_id labels", values.encrypt_vault_id)
    )
  end
end

function M.check()
  health.start("ansible-vault.nvim")

  local v = vim.version()
  if vim.fn.has("nvim-" .. config.MIN_NVIM_VERSION) == 1 then
    health.ok(string.format("Neovim %d.%d.%d", v.major, v.minor, v.patch))
  else
    health.error(
      string.format(
        "Neovim %s is required; this plugin tracks the current release only and does not support older ones",
        config.MIN_NVIM_VERSION
      )
    )
  end

  local executable = cli.executable_argv()[1]
  if vim.fn.executable(executable) == 1 then
    health.ok("ansible-vault executable found: " .. executable)
  else
    health.error("ansible-vault executable not found: " .. executable)
  end

  local values = config.values

  -- The report runs in its own buffer, so resolution starts from the working
  -- directory rather than from a file being edited.
  local resolved = credentials.describe(values, {})

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
        "Ansible's own config supplies a second identity; the plugin's credential is named '%s' and takes precedence",
        resolved.encrypt_label or "default"
      )
    )
  end

  local password_files = credentials.as_list(values.password_files)
  if #password_files > 0 then
    for _, path in ipairs(password_files) do
      check_password_file(path, "password_files")
    end
    if #credentials.as_list(values.vault_ids) > 0 then
      health.info("password_files takes precedence over vault_ids")
    end
  else
    check_vault_ids(values)
    if resolved.source == "interactive" then
      health.warn("No password_files, vault_ids, ANSIBLE_* variable or ansible.cfg found; commands will prompt")
    end
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
end

return M
