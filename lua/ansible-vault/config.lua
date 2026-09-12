---The plugin's configuration, and the rules for merging per-command overrides
---over it.
---
---`M.values` is mutated in place and never rebound, because `setup()` can be
---called more than once and callers hold a reference to it — `:checkhealth`
---reads it directly. Replacing the table would silently detach those references.
local M = {}

---The only Neovim version this plugin targets.
---
---Lives here rather than in the main module because the main module exports
---nothing but `setup`, and `:checkhealth` still has to report the requirement.
M.MIN_NVIM_VERSION = "0.12"

---Persistent plugin configuration.
---
---One key per `ansible-vault` flag, named after it, so there is nothing to learn
---twice: whatever the Ansible documentation tells you to pass, the key is here
---under the same name. `vault_ids` and `password_files` accept a single string or
---a list, because the flags they stand for are repeatable.
---
---Everything that describes a single operation rather than a preference —
---prompting instead of using a stored credential, and the `--new-vault-*` target
---of a rekey — is a command argument only. Storing "always prompt" or "rekey to
---this password" as configuration describes a moment, not a setting.
---@class AnsibleVaultConfig
---@field vault_ids? string|string[] `--vault-id`, for example "prod@~/.vault_pass"
---@field password_files? string|string[] `--vault-password-file`
---@field encrypt_vault_id? string `--encrypt-vault-id`: which identity to encrypt with
---@field ansible_vault_path? string Path to the ansible-vault executable

---@type AnsibleVaultConfig
M.DEFAULTS = {
  vault_ids = nil,
  password_files = nil,
  encrypt_vault_id = nil,
  ansible_vault_path = nil,
}

local TYPES = {
  vault_ids = { "string", "table" },
  password_files = { "string", "table" },
  encrypt_vault_id = { "string" },
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
---An unknown key is an error, so a typo cannot look like it took effect. That is
---also what reports `ask_password`, `new_vault_id` and `new_password_file`: they
---are command arguments, and silently ignoring them in `setup()` would leave the
---user believing every operation prompts, or that a rekey target is configured.
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
---The result is the configuration for one operation, which is why the
---command-only keys appear here and nowhere in `M.values`: they travel with the
---overrides and are gone when the operation ends.
---
---The list-valued keys are replaced wholesale rather than merged:
---`tbl_deep_extend` merges list-like tables element by element, so a single
---`--vault-id x` against a configured list of two would leave the second
---configured entry in place and silently pass a credential the user did not name.
---
---`false` is the "explicitly unset" sentinel a command argument uses to knock out
---a configured credential it replaces; every reader treats it as absent.
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
