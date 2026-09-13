---Credential resolution.
---
---One implementation of the precedence rules, shared by the code that runs
---`ansible-vault` and by `:checkhealth`, so diagnostics report the credential
---source actually being used.
---
---Precedence, highest first:
---
---  1. per-command arguments (`:VaultEncrypt --vault-id prod@...`)
---  2. `setup()` configuration
---  3. `ANSIBLE_*` environment variables
---  4. `ansible.cfg`
---  5. interactive prompt
---
---Layers 3 and 4 are Ansible's own; when nothing above them supplies a credential
---the plugin passes no credential flags at all and just runs in the right
---directory, letting `ansible-vault` resolve them. Passing flags on top of them is
---what triggers "The vault-ids default,default are available to encrypt".
---
---When something above them *does* supply a credential, the precedence has to be
---enforced rather than assumed — see `identity_list_env`, which exists because
---`ansible-vault` otherwise lets `ansible.cfg` outrank the command line.
---
---Interactively entered passwords are handed to the child process through its
---environment and read back by a static helper script that contains no secret. If
---that helper cannot be installed the operation fails; there is no fallback that
---writes the password to a file.
local ansible_cfg = require("ansible-vault.ansible_cfg")

local M = {}

local uv = vim.uv

local PASSWORD_ENV = "ANSIBLE_VAULT_NVIM_PASSWORD"
local IDENTITY_LIST_ENV = "ANSIBLE_VAULT_IDENTITY_LIST"
local ENCRYPT_IDENTITY_ENV = "ANSIBLE_VAULT_ENCRYPT_IDENTITY"
local ASK_ENV = "ANSIBLE_ASK_VAULT_PASS"

local DIR_MODE = 448 -- 0700
local ASKPASS_SCRIPT = "#!/bin/sh\n# Written by ansible-vault.nvim. Contains no secret.\nprintf '%s' \"${"
  .. PASSWORD_ENV
  .. '-}"\n'

local askpass_path = nil

---Extra environment a specific subcommand needs, whatever the credentials are.
---
---`rekey` must not inherit an encrypt identity. `ansible-vault rekey` reads
---`--encrypt-vault-id` *or* `DEFAULT_VAULT_ENCRYPT_IDENTITY`, and if either is
---set it seeds the pool of *new* secrets with the *old* identities from
---`ansible.cfg` (`cli/vault.py`: `if encrypt_vault_id: new_vault_ids =
---default_vault_ids`) before matching by label. With `vault_encrypt_identity` or
---`ANSIBLE_VAULT_ENCRYPT_IDENTITY` set to a label the old configuration also
---carries, the rekey reports "Rekey successful", writes the same 1.2 header back,
---and leaves the file encrypted with the OLD password. Verified against
---ansible-core 2.21.4.
---
---An empty string is the clean way to switch it off: Ansible reads it as a set
---but falsy value, so the default is gone while `DEFAULT_VAULT_IDENTITY_LIST` —
---which is what still decrypts the old content — is untouched. Emptying the
---identity list the same way does not work: `ANSIBLE_VAULT_IDENTITY_LIST=""`
---parses as one empty entry and warns about an unreadable password file.
local ACTION_ENV = {
  rekey = { [ENCRYPT_IDENTITY_ENV] = "" },
}

---@param action string
---@return table|nil
function M.action_env(action)
  return ACTION_ENV[action]
end

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

---The label half of a `label@source` vault id.
---
---A vault id with no `@` is a bare password file, which `ansible-vault` files
---under `DEFAULT_VAULT_IDENTITY` — not under its own path, which is what reading
---the whole string as a label would claim.
---@param vault_id any
---@param default_identity string
---@return string
local function vault_id_label(vault_id, default_identity)
  if not is_nonempty_string(vault_id) then
    return default_identity
  end
  return vault_id:match("^([^@]+)@") or default_identity
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

--- Planning ---------------------------------------------------------------

---@class AnsibleVaultPlan
---@field args string[] Credential flags to pass to ansible-vault
---@field identities string[] `label@source` for each credential the plugin supplies
---@field cwd string|nil Directory the child process should run in
---@field source string Human-readable credential source
---@field our_label string Vault id label the plugin's own credential carries
---@field default_identity string Label a bare password file lands under
---@field needs_password boolean Whether an interactive prompt is required
---@field needs_disambiguation boolean Whether Ansible would supply a second identity
---@field cfg AnsibleVaultCfg Resolved ansible.cfg/environment state

---The flags that hand `source` to `ansible-vault` under `label`.
---
---`--vault-password-file` always lands under `DEFAULT_VAULT_IDENTITY`, so it can
---only be used when that is the label we want. Naming any other label needs
---`--vault-id`, which is also what makes `ansible-vault` write a 1.2 envelope
---carrying it.
---@param label string
---@param source string
---@param default_identity string
---@return string[] args
local function credential_flags(label, source, default_identity)
  if label == default_identity then
    return { "--vault-password-file", source }
  end
  return { "--vault-id", label .. "@" .. source }
end

---Work out where credentials come from, without prompting for anything.
---@param config table Effective plugin configuration
---@param context? { file_path?: string, header_label?: string }
---@return AnsibleVaultPlan
function M.plan(config, context)
  local cfg = ansible_cfg.resolve(context and context.file_path or nil)
  local default_identity = is_nonempty_string(cfg.settings.vault_identity) and cfg.settings.vault_identity or "default"

  local plan = {
    args = {},
    identities = {},
    cwd = cfg.cwd,
    cfg = cfg,
    needs_password = false,
    needs_disambiguation = false,
    our_label = default_identity,
    default_identity = default_identity,
    source = "interactive",
  }

  local password_files = M.as_list(config.password_files)
  local vault_ids = M.as_list(config.vault_ids)

  -- The label the result should carry, when the caller knows one. A password
  -- file has no label of its own, so this is what decides whether re-encrypting
  -- keeps the file's 1.2 identity or quietly rewrites it as 1.1.
  local wanted
  if is_nonempty_string(config.encrypt_vault_id) then
    wanted = config.encrypt_vault_id
  elseif context and is_nonempty_string(context.header_label) then
    wanted = context.header_label
  end

  -- An explicit ask beats everything, including what Ansible's own config would
  -- supply. This is the only way to reach a vault whose password is not written
  -- down anywhere the plugin or Ansible can find it.
  if config.ask_password == true or cfg.settings.ask_vault_pass == true then
    plan.needs_password = true
    plan.source = config.ask_password == true and "ask_password" or "ansible.cfg ask_vault_pass"
    plan.our_label = wanted or default_identity
  elseif #password_files > 0 then
    plan.source = #password_files > 1 and string.format("password_files (%d)", #password_files) or "password_files"
    plan.our_label = wanted or default_identity
    for _, path in ipairs(password_files) do
      local expanded = M.expand_path(path)
      vim.list_extend(plan.args, credential_flags(plan.our_label, expanded, default_identity))
      table.insert(plan.identities, plan.our_label .. "@" .. expanded)
    end
  elseif #vault_ids > 0 then
    plan.source = #vault_ids > 1 and string.format("vault_ids (%d)", #vault_ids) or "vault_ids"
    for _, vault_id in ipairs(vault_ids) do
      local expanded = M.expand_vault_id(vault_id)
      table.insert(plan.args, "--vault-id")
      table.insert(plan.args, expanded)
      table.insert(plan.identities, expanded)
    end
    plan.our_label = vault_id_label(M.expand_vault_id(vault_ids[1]), default_identity)
  elseif cfg.has_credentials then
    -- Ansible resolves these itself; adding flags would create a second identity.
    plan.source = cfg.credential_source or "ansible.cfg"
    plan.our_label = cfg.label or default_identity
  else
    plan.needs_password = true
    plan.our_label = wanted or default_identity
  end

  -- True whenever the child's secret pool can hold more than the one identity
  -- the plugin supplies, which is exactly when the identity to encrypt with has
  -- to be named rather than left to "the only one there is".
  plan.needs_disambiguation = (#plan.args > 0 or plan.needs_password) and cfg.has_credentials

  return plan
end

---Whether the credential the plugin is about to pass carries `label`.
---@param plan AnsibleVaultPlan
---@param label string
---@return boolean
local function carries_label(plan, label)
  if #plan.identities == 0 and not plan.needs_password then
    -- Ansible's own configuration supplies the secrets and we cannot enumerate
    -- them, so name the label and let `ansible-vault` say whether it matched.
    return true
  end
  if plan.our_label == label then
    return true
  end
  for _, identity in ipairs(plan.identities) do
    if vault_id_label(identity, plan.default_identity) == label then
      return true
    end
  end
  return false
end

---Label to encrypt with, or nil to let `ansible-vault` decide.
---
---An explicit setting always wins, even if nothing carries it: the user named an
---identity, and failing is better than encrypting with a different one. Otherwise
---the label already recorded in the file's own
---`$ANSIBLE_VAULT;1.2;AES256;<label>` header is reused, so re-encrypting does not
---silently downgrade the file to format 1.1 and drop its label — but only when
---the credential in hand actually carries that label, because naming one it does
---not carry would either fail outright or match some *other* identity that
---happens to share the name.
---@param config table
---@param plan AnsibleVaultPlan
---@param context? { header_label?: string }
---@return string|nil
function M.encrypt_label(config, plan, context)
  if is_nonempty_string(config.encrypt_vault_id) then
    return config.encrypt_vault_id
  end

  local header = context and context.header_label
  if is_nonempty_string(header) and carries_label(plan, header) then
    return header
  end

  if plan.needs_disambiguation then
    return plan.our_label
  end

  -- Several password files are one credential set under one label, so there is
  -- nothing for the user to choose between — but `ansible-vault` counts secrets,
  -- not labels, and refuses with "The vault-ids default,default are available to
  -- encrypt" unless the label is spelled out. Several vault ids under *different*
  -- labels is a real choice, and is left to fail rather than picking one.
  if #plan.identities > 1 then
    for _, identity in ipairs(plan.identities) do
      if vault_id_label(identity, plan.default_identity) ~= plan.our_label then
        return nil
      end
    end
    return plan.our_label
  end

  return nil
end

--- Resolution -------------------------------------------------------------

---@class AnsibleVaultCredentials
---@field args string[] Credential flags
---@field env table|nil Extra environment for the child process
---@field cwd string|nil Working directory for the child process
---@field plan? AnsibleVaultPlan Absent for the rekey target's own credentials

---Put the plugin's own identities ahead of Ansible's own, for the child only.
---
---`ansible-vault` builds its secret pool as `DEFAULT_VAULT_IDENTITY_LIST` first
---and the `--vault-id` flags after it, then encrypts with the FIRST secret whose
---label matches. So an `ansible.cfg` that happens to use the same label as the
---credential the user named on the command line wins, and the file is encrypted
---with a password the user did not choose — exit 0, the expected header, the
---wrong key. Verified against ansible-core 2.21.4.
---
---Prepending our identities restores the documented precedence without touching
---the user's `ansible.cfg` or this process's environment. The configured entries
---are kept after ours, so content encrypted with one of them still decrypts.
---@param plan AnsibleVaultPlan
---@param identities string[]
---@return table|nil env
---@return string|nil err
local function identity_list_env(plan, identities)
  local configured = plan.cfg.settings.vault_identity_list
  if #identities == 0 or type(configured) ~= "table" or #configured == 0 then
    return nil, nil
  end

  local entries = vim.list_extend(vim.deepcopy(identities), configured)
  for _, entry in ipairs(entries) do
    if entry:find(",", 1, true) then
      -- The variable is comma separated with no escape, so a source containing
      -- one cannot be expressed. Failing is the only safe answer: continuing
      -- would encrypt with ansible.cfg's password instead of the named one.
      return nil, string.format("a vault id source contains a comma, which %s cannot express", IDENTITY_LIST_ENV)
    end
  end

  return { [IDENTITY_LIST_ENV] = table.concat(entries, ",") }, nil
end

---@param plan AnsibleVaultPlan
---@param identities string[]
---@param extra? table
---@return table|nil env
---@return string|nil err
local function child_env(plan, identities, extra)
  -- The plugin is supplying the secret, so the child must not also try to
  -- prompt: `ansible.cfg` may set `ask_vault_pass`, and with piped stdin and no
  -- tty that either blocks until the timeout or reads the content as a password.
  local env = { [ASK_ENV] = "False" }

  local isolation, err = identity_list_env(plan, identities)
  if err then
    return nil, err
  end

  -- The child must read the same config this plan was built from, not whatever
  -- its working directory happens to offer it.
  local from_cfg = ansible_cfg.config_env(plan.cfg)

  return vim.tbl_extend("force", env, from_cfg, isolation or {}, extra or {}), nil
end

---Resolve credentials, prompting only when nothing else supplies them.
---@param config table Effective plugin configuration
---@param context? { file_path?: string, header_label?: string }
---@param callback fun(creds: AnsibleVaultCredentials|nil)
function M.resolve(config, context, callback)
  local plan = M.plan(config, context)

  if not plan.needs_password then
    local env, err = child_env(plan, plan.identities, nil)
    if not env then
      vim.notify("Cannot run ansible-vault: " .. err, vim.log.levels.ERROR)
      callback(nil)
      return
    end
    callback({ args = plan.args, env = env, cwd = plan.cwd, plan = plan })
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

  -- Fail closed. The only other way to hand a typed password to `ansible-vault`
  -- is a file, and a file is exactly what this plugin promises never to write.
  local helper, helper_err = ensure_askpass()
  if not helper then
    vim.notify(
      "Cannot pass the vault password without writing it to disk ("
        .. (helper_err or "unknown reason")
        .. "); use password_files or vault_ids instead",
      vim.log.levels.ERROR
    )
    callback(nil)
    return
  end

  local env, env_err = child_env(plan, { plan.our_label .. "@" .. helper }, { [PASSWORD_ENV] = password })
  if not env then
    vim.notify("Cannot run ansible-vault: " .. env_err, vim.log.levels.ERROR)
    callback(nil)
    return
  end

  callback({
    args = credential_flags(plan.our_label, helper, plan.default_identity),
    env = env,
    cwd = plan.cwd,
    plan = plan,
  })
end

--- Rekey -----------------------------------------------------------------

---Build the `--new-*` argv for `ansible-vault rekey`.
---
---`--encrypt-vault-id` must NOT appear here, even though it is correct for
---`encrypt` and `encrypt_string`. For `rekey` alone, passing it makes Ansible seed
---the *new* secret pool with the *old* identities from `ansible.cfg`
---(`cli/vault.py`: `if encrypt_vault_id: new_vault_ids = default_vault_ids`) and
---then pick from that mixed pool by label. So a 1.2 file labelled `prod` either
---fails with "Did not find a match for --encrypt-vault-id=prod" when no old
---identity carries the label, or — worse — is silently re-encrypted with the OLD
---password when one does, and reports success. `ACTION_ENV.rekey` closes the same
---hole for the inherited default.
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

---Credentials that encrypt with the rekey target, and with nothing else.
---
---`ansible-vault rekey` does the two halves itself, but inline rekey cannot use
---it: the ciphertext lives inside a YAML file that must keep its structure, so
---the value is decrypted and re-encrypted as two runs. The second run must not
---inherit the first one's secret pool — with `ansible.cfg` supplying an identity
---under the same label, "encrypt with the new password" would resolve to the old
---one, and the rekey would appear to succeed while changing nothing.
---
---So the new identity is the only one the child can see, and it is named
---explicitly rather than left to a pool of one.
---@param config table Effective plugin configuration
---@param context? { file_path?: string, header_label?: string }
---@return AnsibleVaultCredentials|nil creds, string|nil err
function M.new_credentials(config, context)
  local args, err = M.rekey_args(config, context)
  if err then
    return nil, err
  end
  if not args then
    return nil, nil
  end

  local cfg = ansible_cfg.resolve(context and context.file_path or nil)
  local default_identity = is_nonempty_string(cfg.settings.vault_identity) and cfg.settings.vault_identity or "default"

  local identity = args[1] == "--new-vault-id" and args[2] or (default_identity .. "@" .. args[2])
  local label = vault_id_label(identity, default_identity)

  if identity:find(",", 1, true) then
    return nil, string.format("a vault id source contains a comma, which %s cannot express", IDENTITY_LIST_ENV)
  end

  return {
    args = { "--vault-id", identity, "--encrypt-vault-id", label },
    -- The same config the decrypt half read, so this run resolves the project's
    -- settings rather than none at all; the identity list below still replaces
    -- its credentials, which is what keeps the new secret the only one.
    env = vim.tbl_extend("force", ansible_cfg.config_env(cfg), {
      [ASK_ENV] = "False",
      -- Replaces whatever `ansible.cfg` configured, so the old identities cannot
      -- take the label ahead of this one.
      [IDENTITY_LIST_ENV] = identity,
      [ENCRYPT_IDENTITY_ENV] = "",
    }),
    cwd = cfg.cwd,
  },
    nil
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

return M
