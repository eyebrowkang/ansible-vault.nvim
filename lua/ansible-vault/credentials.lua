---Credential resolution.
---
---One implementation of the precedence rules, shared by the code that runs
---`ansible-vault` and by `:checkhealth`, so diagnostics report the credential
---source actually being used.
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

local uv = vim.uv

local PASSWORD_ENV = "ANSIBLE_VAULT_NVIM_PASSWORD"
local PASSWORD_FILE_MODE = 384 -- 0600
local DIR_MODE = 448 -- 0700
local ASKPASS_SCRIPT = "#!/bin/sh\n# Written by ansible-vault.nvim. Contains no secret.\nprintf '%s' \"${"
  .. PASSWORD_ENV
  .. '-}"\n'

local askpass_path = nil

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

---Normalize a "string or list" config value to a list of non-empty strings.
---
---The flags these stand for are repeatable, so the plural form is the real
---shape; accepting a bare string keeps the common single-credential case from
---having to be written as a one-element table.
---@param value any
---@return string[]
function M.as_list(value)
  if is_nonempty_string(value) then
    return { value }
  end
  if type(value) ~= "table" then
    return {}
  end
  local result = {}
  for _, item in ipairs(value) do
    if is_nonempty_string(item) then
      table.insert(result, item)
    end
  end
  return result
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

  local base = vim.fn.stdpath("run")
  if not is_nonempty_string(base) then
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

  local password_files = M.as_list(config.password_files)
  local vault_ids = M.as_list(config.vault_ids)

  -- An explicit ask beats everything, including what Ansible's own config would
  -- supply. This is the only way to reach a vault whose password is not written
  -- down anywhere the plugin or Ansible can find it.
  if config.ask_password == true or cfg.settings.ask_vault_pass == true then
    plan.needs_password = true
    plan.source = config.ask_password == true and "ask_password" or "ansible.cfg ask_vault_pass"
  elseif #password_files > 0 then
    plan.source = #password_files > 1 and string.format("password_files (%d)", #password_files) or "password_files"
    for _, path in ipairs(password_files) do
      table.insert(plan.args, "--vault-password-file")
      table.insert(plan.args, M.expand_path(path))
    end
    plan.our_label = cfg.settings.vault_identity or "default"
  elseif #vault_ids > 0 then
    plan.source = #vault_ids > 1 and string.format("vault_ids (%d)", #vault_ids) or "vault_ids"
    for _, vault_id in ipairs(vault_ids) do
      table.insert(plan.args, "--vault-id")
      table.insert(plan.args, M.expand_vault_id(vault_id))
    end
    plan.our_label = vault_id_label(M.expand_vault_id(vault_ids[1]))
  elseif cfg.has_credentials then
    -- Ansible resolves these itself; adding flags would create a second identity.
    plan.source = cfg.credential_source or "ansible.cfg"
    plan.our_label = cfg.label
  else
    plan.needs_password = true
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
      env = { [PASSWORD_ENV] = password, ANSIBLE_ASK_VAULT_PASS = "False" },
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
    env = { ANSIBLE_ASK_VAULT_PASS = "False" },
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
    -- The plugin is supplying the secret, so the child must not also try to
    -- prompt: `ansible.cfg` may set `ask_vault_pass`, and with piped stdin and no
    -- tty that either blocks until the timeout or reads the content as a password.
    callback({
      args = plan.args,
      env = { ANSIBLE_ASK_VAULT_PASS = "False" },
      cwd = plan.cwd,
      plan = plan,
    })
    return
  end

  -- Never held beyond the operation that needs it: the prompt runs per
  -- operation, and the password lives only in this local and the child's
  -- environment. Caching it would put a secret in the Lua heap for a window the
  -- user cannot see or audit.
  local ok, password = pcall(vim.fn.inputsecret, "Ansible Vault Password: ")
  vim.cmd("redraw")

  if not ok or not is_nonempty_string(password) then
    vim.notify("Password is required", vim.log.levels.ERROR)
    callback(nil)
    return
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

---Describe credential resolution for `:checkhealth` without side effects.
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
    needs_disambiguation = plan.needs_disambiguation,
    encrypt_label = M.encrypt_label(config, plan, context),
    settings = plan.cfg.settings,
  }
end

---Build the `--new-*` argv for `ansible-vault rekey`.
---
---`--encrypt-vault-id` must NOT appear here, even though it is correct for
---`encrypt` and `encrypt_string`. For `rekey` alone, passing it makes Ansible seed
---the *new* secret pool with the *old* identities from `ansible.cfg`
---(`cli/vault.py`: `if encrypt_vault_id: new_vault_ids = default_vault_ids`) and
---then pick from that mixed pool by label. So a 1.2 file labelled `prod` either
---fails with "Did not find a match for --encrypt-vault-id=prod" when no old
---identity carries the label, or — worse — is silently re-encrypted with the OLD
---password when one does, and reports success.
---
---A label is preserved instead by naming it on the new identity itself:
---`--new-vault-id <label>@<source>` makes the new id non-default, which is what
---makes Ansible write a 1.2 envelope carrying that label.
---@param config table Effective plugin configuration
---@param context? { header_label?: string }
---@return string[]|nil args, string|nil err
function M.rekey_args(config, context)
  local new_vault_id = config.new_vault_id
  local new_password_file = config.new_password_file

  if is_nonempty_string(new_vault_id) and is_nonempty_string(new_password_file) then
    return nil, "new_vault_id and new_password_file are mutually exclusive"
  end

  if is_nonempty_string(new_vault_id) then
    return { "--new-vault-id", M.expand_vault_id(new_vault_id) }, nil
  end

  if is_nonempty_string(new_password_file) then
    local path = M.expand_path(new_password_file)

    -- Keep a 1.2 label alive across the rekey. Without a label on the new
    -- identity, a password file resolves to the id "default" and Ansible writes
    -- a 1.1 envelope, dropping the label the file used to carry.
    local label = config.encrypt_vault_id
    if not is_nonempty_string(label) then
      label = context and context.header_label or nil
    end
    if is_nonempty_string(label) and label ~= "default" then
      return { "--new-vault-id", label .. "@" .. path }, nil
    end

    return { "--new-vault-password-file", path }, nil
  end

  return nil, nil
end

M._private = {
  ensure_askpass = ensure_askpass,
  password_env = PASSWORD_ENV,
}

return M
