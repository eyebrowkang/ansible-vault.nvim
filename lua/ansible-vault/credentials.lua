---Credential resolution.
---
---One implementation of the precedence rules, shared by the code that actually
---runs `ansible-vault`, by `:VaultInfo`, and by `:checkhealth`. Keeping these in
---sync matters: when they drift, the diagnostics confidently report a credential
---source that is not the one being used.
---
---Precedence, highest first:
---
---  1. per-command overrides (`:VaultEncrypt --vault-id prod@...`)
---  2. `setup()` configuration
---  3. `ANSIBLE_*` environment variables
---  4. `ansible.cfg`
---  5. interactive prompt
---
---Layers 3 and 4 are Ansible's own; for those the plugin passes no credential
---flags at all and just runs in the right directory, letting `ansible-vault`
---resolve them. Passing flags on top of them is what triggers
---"The vault-ids default,default are available to encrypt".
---
---Interactively entered passwords are handed to the child process through its
---environment and read back by a static helper script that contains no secret.
---Nothing secret is ever written to disk.
local ansible_cfg = require("ansible-vault.ansible_cfg")

local M = {}

local uv = vim.uv or vim.loop

local PASSWORD_ENV = "ANSIBLE_VAULT_NVIM_PASSWORD"
local PASSWORD_FILE_MODE = 384 -- 0600
local DIR_MODE = 448 -- 0700
local ASKPASS_SCRIPT = "#!/bin/sh\n# Written by ansible-vault.nvim. Contains no secret.\nprintf '%s' \"${"
  .. PASSWORD_ENV
  .. '-}"\n'

local askpass_path = nil

---@type { password: string|nil, expires_at: number, timer: userdata|nil }
local password_cache = { password = nil, expires_at = 0, timer = nil }

---Temp password files created by the fallback path, so they can be swept if an
---operation never completes.
---@type table<string, boolean>
local pending_tempfiles = {}

---@param value any
---@return boolean
local function is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

---@param path string
---@return string
function M.expand_path(path)
  return vim.fn.expand(path)
end

---Expand the source half of a `label@source` vault id, leaving Ansible's magic
---`prompt` sources alone.
---@param vault_id string
---@return string
function M.expand_vault_id(vault_id)
  local label, source = vault_id:match("^([^@]+)@(.+)$")
  if not label or not source or source == "prompt" or source == "prompt_ask_vault_pass" then
    return vault_id
  end
  return label .. "@" .. M.expand_path(source)
end

---@param vault_id any
---@return string|nil
local function vault_id_label(vault_id)
  if not is_nonempty_string(vault_id) then
    return nil
  end
  return vault_id:match("^([^@]+)@") or vault_id
end

--- Password helper script -------------------------------------------------

---@return string|nil path
---@return string|nil err
local function ensure_askpass()
  if askpass_path and uv.fs_stat(askpass_path) then
    return askpass_path, nil
  end

  if not uv.getuid then
    return nil, "no POSIX uid support"
  end

  local ok, base = pcall(vim.fn.stdpath, "run")
  if not ok or not is_nonempty_string(base) then
    return nil, "stdpath('run') is unavailable"
  end

  local dir = base .. "/ansible-vault.nvim"
  uv.fs_mkdir(dir, DIR_MODE)

  local dir_stat = uv.fs_stat(dir)
  if not dir_stat or dir_stat.type ~= "directory" then
    return nil, "could not create " .. dir
  end
  if dir_stat.uid ~= uv.getuid() then
    return nil, dir .. " is not owned by the current user"
  end
  if dir_stat.mode % 512 ~= DIR_MODE and not uv.fs_chmod(dir, DIR_MODE) then
    return nil, "could not restrict permissions on " .. dir
  end

  -- Written through a rename so a second Neovim starting at the same moment
  -- never observes the script mid-truncation and reads an empty password.
  local path = dir .. "/askpass.sh"
  local tmp = string.format("%s.%d", path, uv.getpid())

  local fd, open_err = uv.fs_open(tmp, "w", DIR_MODE)
  if not fd then
    return nil, open_err or ("could not write " .. path)
  end
  uv.fs_write(fd, ASKPASS_SCRIPT)
  uv.fs_close(fd)
  uv.fs_chmod(tmp, DIR_MODE)

  local renamed, rename_err = uv.fs_rename(tmp, path)
  if not renamed then
    os.remove(tmp)
    return nil, rename_err or ("could not install " .. path)
  end

  askpass_path = path
  return path, nil
end

---Fallback for platforms where the helper script cannot be used. The file is
---named after the owning process so a stale one can be identified and swept.
---@param contents string
---@return string|nil path
---@return string|nil err
local function write_password_tempfile(contents)
  local path = string.format("%s.ansible-vault-nvim.%d", vim.fn.tempname(), uv.getpid())
  local fd, open_err = uv.fs_open(path, "wx", PASSWORD_FILE_MODE)
  if not fd then
    return nil, open_err or "failed to create temp file"
  end

  local written, write_err = uv.fs_write(fd, contents)
  uv.fs_close(fd)

  if type(written) ~= "number" or written < #contents then
    os.remove(path)
    return nil, write_err or "failed to write temp file"
  end

  pending_tempfiles[path] = true
  return path, nil
end

---@param path string
local function remove_password_tempfile(path)
  pending_tempfiles[path] = nil
  os.remove(path)
end

---Remove every temp password file this process still owns.
function M.cleanup_all()
  for path in pairs(pending_tempfiles) do
    os.remove(path)
  end
  pending_tempfiles = {}
end

--- Password cache ---------------------------------------------------------

---@param ttl any
---@return boolean
local function should_cache(ttl)
  return type(ttl) == "number" and ttl > 0
end

function M.clear_password_cache()
  password_cache.password = nil
  password_cache.expires_at = 0
  if password_cache.timer and not password_cache.timer:is_closing() then
    password_cache.timer:stop()
    password_cache.timer:close()
  end
  password_cache.timer = nil
end

---@param password string
---@param ttl number
local function cache_password(password, ttl)
  M.clear_password_cache()
  password_cache.password = password
  password_cache.expires_at = os.time() + ttl

  -- Expire eagerly. A lazy check would leave the password in the Lua heap until
  -- the next vault operation, which may never come.
  local timer = uv.new_timer()
  if timer then
    password_cache.timer = timer
    timer:start(ttl * 1000, 0, function()
      vim.schedule(function()
        M.clear_password_cache()
      end)
    end)
  end
end

---@return string|nil
local function cached_password(ttl)
  if not should_cache(ttl) then
    return nil
  end
  if password_cache.password and password_cache.expires_at > os.time() then
    return password_cache.password
  end
  return nil
end

---@param ttl any
---@return string
function M.describe_cache(ttl)
  if not should_cache(ttl) then
    return "disabled"
  end
  if password_cache.password and password_cache.expires_at > os.time() then
    return string.format("active (%ds remaining)", password_cache.expires_at - os.time())
  end
  return "enabled, empty"
end

--- Planning ---------------------------------------------------------------

---@class AnsibleVaultPlan
---@field args string[] Credential flags to pass to ansible-vault
---@field cwd string|nil Directory the child process should run in
---@field source string Human-readable credential source
---@field our_label string|nil Vault id label the plugin's own credential carries
---@field needs_password boolean Whether an interactive prompt is required
---@field needs_disambiguation boolean Whether Ansible would supply a second identity
---@field cfg AnsibleVaultCfg Resolved ansible.cfg/environment state

---Work out where credentials come from, without prompting for anything.
---@param config table Effective plugin configuration
---@param context? { file_path?: string }
---@return AnsibleVaultPlan
function M.plan(config, context)
  local cfg = ansible_cfg.resolve(context and context.file_path or nil)
  local plan = {
    args = {},
    cwd = cfg.cwd,
    cfg = cfg,
    needs_password = false,
    needs_disambiguation = false,
    our_label = nil,
    source = "interactive",
  }

  if is_nonempty_string(config.password_file) then
    plan.source = "password_file"
    plan.args = { "--vault-password-file", M.expand_path(config.password_file) }
    plan.our_label = cfg.settings.vault_identity or "default"
  else
    local vault_ids = {}
    if type(config.vault_ids) == "table" then
      for _, vault_id in ipairs(config.vault_ids) do
        if is_nonempty_string(vault_id) then
          table.insert(vault_ids, M.expand_vault_id(vault_id))
        end
      end
    end
    if #vault_ids == 0 and is_nonempty_string(config.vault_id) then
      table.insert(vault_ids, M.expand_vault_id(config.vault_id))
    end

    if #vault_ids > 0 then
      plan.source = #vault_ids > 1 and string.format("vault_ids (%d)", #vault_ids) or "vault_id"
      for _, vault_id in ipairs(vault_ids) do
        table.insert(plan.args, "--vault-id")
        table.insert(plan.args, vault_id)
      end
      plan.our_label = vault_id_label(vault_ids[1])
    elseif cfg.has_credentials then
      -- Ansible resolves these itself; adding flags would create a second identity.
      plan.source = cfg.credential_source or "ansible.cfg"
      plan.our_label = cfg.label
    else
      plan.needs_password = true
    end
  end

  plan.needs_disambiguation = #plan.args > 0 and cfg.has_credentials

  return plan
end

---Label to encrypt with, or nil to let `ansible-vault` decide.
---
---An explicit setting always wins. Otherwise the label already recorded in the
---file's own `$ANSIBLE_VAULT;1.2;AES256;<label>` header is reused, so re-encrypting
---does not silently downgrade the file to format 1.1 and drop its label.
---@param config table
---@param plan AnsibleVaultPlan
---@param context? { header_label?: string }
---@return string|nil
function M.encrypt_label(config, plan, context)
  if is_nonempty_string(config.encrypt_vault_id) then
    return config.encrypt_vault_id
  end
  if context and is_nonempty_string(context.header_label) then
    return context.header_label
  end
  if plan.needs_disambiguation then
    return plan.our_label or "default"
  end
  return nil
end

--- Resolution -------------------------------------------------------------

---@class AnsibleVaultCredentials
---@field args string[] Credential flags
---@field env table|nil Extra environment for the child process
---@field cwd string|nil Working directory for the child process
---@field plan AnsibleVaultPlan
---@field cleanup fun()|nil

---@param plan AnsibleVaultPlan
---@param password string
---@return AnsibleVaultCredentials|nil
---@return string|nil err
local function credentials_for_password(plan, password)
  local helper, helper_err = ensure_askpass()
  if helper then
    return {
      args = { "--vault-password-file", helper },
      env = { [PASSWORD_ENV] = password },
      cwd = plan.cwd,
      plan = plan,
    },
      nil
  end

  local tmpfile, temp_err = write_password_tempfile(password .. "\n")
  if not tmpfile then
    return nil, temp_err or helper_err
  end

  local cleaned = false
  return {
    args = { "--vault-password-file", tmpfile },
    cwd = plan.cwd,
    plan = plan,
    cleanup = function()
      if cleaned then
        return
      end
      cleaned = true
      remove_password_tempfile(tmpfile)
    end,
  },
    nil
end

---Resolve credentials, prompting only when nothing else supplies them.
---@param config table Effective plugin configuration
---@param context? { file_path?: string }
---@param callback fun(creds: AnsibleVaultCredentials|nil)
function M.resolve(config, context, callback)
  local plan = M.plan(config, context)

  if not plan.needs_password then
    callback({ args = plan.args, cwd = plan.cwd, plan = plan })
    return
  end

  local password = cached_password(config.password_cache_ttl)
  if not password then
    local ok, entered = pcall(vim.fn.inputsecret, "Ansible Vault Password: ")
    vim.cmd("redraw")

    if not ok or not is_nonempty_string(entered) then
      vim.notify("Password is required", vim.log.levels.ERROR)
      callback(nil)
      return
    end

    password = entered
    if should_cache(config.password_cache_ttl) then
      cache_password(password, config.password_cache_ttl)
    else
      M.clear_password_cache()
    end
  end

  local creds, err = credentials_for_password(plan, password)
  if not creds then
    vim.notify("Failed to prepare vault password: " .. (err or "unknown error"), vim.log.levels.ERROR)
    callback(nil)
    return
  end

  callback(creds)
end

--- Diagnostics ------------------------------------------------------------

---Describe credential resolution for `:VaultInfo` and `:checkhealth`, without
---side effects.
---@param config table
---@param context? { file_path?: string }
---@return table
function M.describe(config, context)
  local plan = M.plan(config, context)
  return {
    source = plan.source,
    cwd = plan.cwd,
    cfg_path = plan.cfg.cfg_path,
    cfg_source = plan.cfg.cfg_source,
    ansible_supplies = plan.cfg.has_credentials,
    needs_disambiguation = plan.needs_disambiguation,
    our_label = plan.our_label,
    encrypt_label = M.encrypt_label(config, plan, context),
    settings = plan.cfg.settings,
  }
end

M._private = {
  ensure_askpass = ensure_askpass,
  password_env = PASSWORD_ENV,
}

return M
