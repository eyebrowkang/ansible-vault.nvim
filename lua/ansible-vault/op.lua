---The plumbing every vault operation shares.
---
---Resolve credentials for the target file and decide which identity to encrypt
---with. `rekey` has separate identity rules because `--encrypt-vault-id` can
---silently re-encrypt with the old password there.
---
---Credential *policy* still lives in `credentials.lua`. This module only threads
---the effective configuration through to it.
local M = {}

local config = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")

---Resolve credentials for an operation, prompting only if nothing supplies them.
---@param callback fun(creds: AnsibleVaultCredentials|nil)
---@param opts? table
---@param context? { file_path?: string, header_label?: string }
function M.credentials(callback, opts, context)
  credentials.resolve(config.effective(opts), context or {}, callback)
end

---Credentials that encrypt with a rekey's target identity and nothing else.
---
---For inline rekey, which decrypts and re-encrypts as two separate runs and must
---not let the first run's secret pool decide what the second one encrypts with.
---Returns `nil, nil` when no rekey target was configured or named.
---@param opts? table
---@param context? { file_path?: string, header_label?: string }
---@return AnsibleVaultCredentials|nil creds, string|nil err
function M.new_credentials(opts, context)
  return credentials.new_credentials(config.effective(opts), context or {})
end

---Append `--encrypt-vault-id` when a specific identity must be named: because the
---user configured one, because the file's own 1.2 header records one that would
---otherwise be lost, or because Ansible's config contributes a second identity and
---leaving the choice implicit is an error.
---
---Correct for `encrypt` and `encrypt_string`, whose secret pool is built from the
---ids actually passed to them. NOT correct for `rekey` — see
---`credentials.rekey_args`.
---@param args string[]
---@param opts? table
---@param creds? AnsibleVaultCredentials
---@param context? table
---@return string[]
function M.with_encrypt_vault_id(args, opts, creds, context)
  local effective = config.effective(opts)
  local result = vim.deepcopy(args or {})

  local label
  if creds and creds.plan then
    label = credentials.encrypt_label(effective, creds.plan, context)
  elseif config.is_nonempty_string(effective.encrypt_vault_id) then
    label = effective.encrypt_vault_id
  end

  if config.is_nonempty_string(label) then
    table.insert(result, "--encrypt-vault-id")
    table.insert(result, label)
  end
  return result
end

return M
