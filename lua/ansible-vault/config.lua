---The plugin's configuration, and the rules for merging per-command overrides
---over it.
---
---`M.values` is mutated in place and never rebound, because `setup()` can be
---called more than once and callers hold a reference to it — the main module
---re-exports it as `vault.config`, and `:checkhealth` reads it. Replacing the
---table would silently detach every one of those references.
local M = {}

---Plugin configuration.
---
---One key per `ansible-vault` flag, named after it, so there is nothing to learn
---twice: whatever the Ansible documentation tells you to pass, the key is here
---under the same name. `vault_ids` and `password_files` accept a single string or
---a list, because the flags they stand for are repeatable.
---@class AnsibleVaultConfig
---@field vault_ids? string|string[] `--vault-id`, for example "prod@~/.vault_pass"
---@field password_files? string|string[] `--vault-password-file`
---@field ask_password? boolean Always prompt, ignoring any configured or discovered credential
---@field encrypt_vault_id? string `--encrypt-vault-id`: which identity to encrypt with
---@field new_vault_id? string `--new-vault-id` for VaultRekey
---@field new_password_file? string `--new-vault-password-file` for VaultRekey
---@field ansible_vault_path? string Path to the ansible-vault executable

---@type AnsibleVaultConfig
M.DEFAULTS = {
  vault_ids = nil,
  password_files = nil,
  ask_password = false,
  encrypt_vault_id = nil,
  new_vault_id = nil,
  new_password_file = nil,
  ansible_vault_path = nil,
}

local TYPES = {
  vault_ids = { "string", "table" },
  password_files = { "string", "table" },
  ask_password = { "boolean" },
  encrypt_vault_id = { "string" },
  new_vault_id = { "string" },
  new_password_file = { "string" },
  ansible_vault_path = { "string" },
}

---Keys holding a repeatable flag, which must be replaced rather than merged.
local LISTS = { "vault_ids", "password_files" }

---@type AnsibleVaultConfig
M.values = vim.deepcopy(M.DEFAULTS)

---@param value any
---@return boolean
function M.is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

---Check a user-supplied config, reporting everything wrong with it at once.
---
---An unknown key is an error, so a typo cannot look like it took effect.
---@param opts table
---@return string[] errors
function M.validate(opts)
  local errors = {}

  for key, value in pairs(opts) do
    local expected = TYPES[key]
    if not expected then
      table.insert(errors, string.format("unknown option: %s", key))
    elseif not vim.tbl_contains(expected, type(value)) then
      table.insert(errors, string.format("%s must be %s, got %s", key, table.concat(expected, " or "), type(value)))
    end
  end

  -- `ansible-vault` puts --ask-vault-password and --vault-password-file in a
  -- mutually exclusive group, so configuring both cannot mean anything.
  if opts.ask_password == true and (opts.password_files ~= nil or opts.vault_ids ~= nil) then
    table.insert(errors, "ask_password cannot be combined with password_files or vault_ids")
  end

  if opts.new_vault_id ~= nil and opts.new_password_file ~= nil then
    table.insert(errors, "new_vault_id and new_password_file are mutually exclusive")
  end

  return errors
end

---Replace the configuration with defaults plus `opts`, in place.
---@param opts AnsibleVaultConfig
function M.apply(opts)
  for key in pairs(M.values) do
    M.values[key] = nil
  end
  for key, value in pairs(vim.tbl_deep_extend("force", vim.deepcopy(M.DEFAULTS), opts)) do
    M.values[key] = value
  end
end

---Merge per-command overrides over the configured defaults.
---
---The list-valued keys are replaced wholesale rather than merged:
---`tbl_deep_extend` merges list-like tables element by element, so a single
---`--vault-id x` against a configured list of two would leave the second
---configured entry in place and silently pass a credential the user did not name.
---@param opts? table
---@return table
function M.effective(opts)
  local overrides = opts and (opts.overrides or opts) or {}
  local config = vim.tbl_deep_extend("force", M.values, overrides)
  for _, key in ipairs(LISTS) do
    if overrides[key] ~= nil then
      config[key] = overrides[key]
    end
  end
  return config
end

---@param message string
---@param level integer
function M.notify(message, level)
  vim.notify(message, level)
end

return M
