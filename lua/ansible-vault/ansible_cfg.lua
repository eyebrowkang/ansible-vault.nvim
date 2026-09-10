---Discovery of `ansible.cfg` and `ANSIBLE_*` environment variables.
---
---Ansible only looks for `ansible.cfg` in the process working directory; it does
---not walk upward. In an editor the working directory is rarely the playbook
---directory, so this module walks up from the buffer's own file instead, and then
---runs `ansible-vault` with its cwd set to the directory the config was found in.
---Relative paths inside the config then resolve exactly the way Ansible resolves
---them, which is relative to the config file itself.
---
---Knowing what Ansible would resolve on its own also lets the plugin stay out of
---the way: passing `--vault-password-file` when `ansible.cfg` already supplies one
---makes `ansible-vault encrypt` fail outright with
---"The vault-ids default,default are available to encrypt".
local M = {}

local uv = vim.uv

local CONFIG_NAMES = { "ansible.cfg", ".ansible.cfg" }

local KEYS = {
  vault_password_file = "path",
  vault_identity_list = "list",
  vault_identity = "string",
  vault_encrypt_identity = "string",
  vault_id_match = "boolean",
  ask_vault_pass = "boolean",
}

---@type table<string, table>
local cache = {}

function M.clear_cache()
  cache = {}
end

---@param value string
---@return boolean
local function truthy(value)
  local lowered = value:lower()
  return lowered == "1" or lowered == "true" or lowered == "yes" or lowered == "on"
end

---Resolve a path the way Ansible does: `~` expands, and a relative path is taken
---relative to the config file that declared it.
---@param value string
---@param base_dir string|nil
---@return string
local function resolve_path(value, base_dir)
  local expanded = vim.fn.expand(value)
  if expanded:sub(1, 1) == "/" or not base_dir then
    return expanded
  end
  return base_dir .. "/" .. expanded
end

---A vault id is `label@source`; only the source half is a path.
---@param value string
---@param base_dir string|nil
---@return string
local function resolve_vault_id(value, base_dir)
  local label, source = value:match("^([^@]+)@(.+)$")
  if not label or not source or source == "prompt" or source == "prompt_ask_vault_pass" then
    return value
  end
  return label .. "@" .. resolve_path(source, base_dir)
end

---Minimal `[defaults]` reader.
---
---Python's configparser keeps `#` that appears mid-value, so only whole-line
---comments are stripped here. Both `key = value` and `key: value` are accepted,
---matching configparser.
---@param path string
---@return table|nil
local function parse_ini(path)
  local file = io.open(path, "r")
  if not file then
    return nil
  end

  local settings = {}
  local section = nil
  local base_dir = vim.fn.fnamemodify(path, ":h")

  for line in file:lines() do
    line = line:gsub("\r$", "")
    local trimmed = line:match("^%s*(.-)%s*$")

    if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" and trimmed:sub(1, 1) ~= ";" then
      local header = trimmed:match("^%[(.-)%]$")
      if header then
        section = header:lower()
      elseif section == "defaults" then
        local key, value = trimmed:match("^([%w_]+)%s*[=:]%s*(.*)$")
        if key then
          local kind = KEYS[key:lower()]
          if kind == "path" then
            settings[key:lower()] = resolve_path(value, base_dir)
          elseif kind == "list" then
            local entries = {}
            for entry in value:gmatch("[^,]+") do
              local item = entry:match("^%s*(.-)%s*$")
              if item ~= "" then
                table.insert(entries, resolve_vault_id(item, base_dir))
              end
            end
            settings[key:lower()] = entries
          elseif kind == "boolean" then
            settings[key:lower()] = truthy(value)
          elseif kind == "string" then
            settings[key:lower()] = value
          end
        end
      end
    end
  end

  file:close()
  return settings
end

---@param path string
---@return string|nil
local function config_from_env()
  local configured = vim.env.ANSIBLE_CONFIG
  if not configured or configured == "" then
    return nil
  end

  local expanded = vim.fn.expand(configured)
  local stat = uv.fs_stat(expanded)
  if not stat then
    return nil
  end
  if stat.type == "directory" then
    for _, name in ipairs(CONFIG_NAMES) do
      local candidate = expanded .. "/" .. name
      if uv.fs_stat(candidate) then
        return candidate
      end
    end
    return nil
  end

  return expanded
end

---@param start_dir string|nil
---@return string|nil path
---@return string source
local function find_config(start_dir)
  local from_env = config_from_env()
  if from_env then
    return from_env, "ANSIBLE_CONFIG"
  end

  if start_dir and start_dir ~= "" then
    local found = vim.fs.find(CONFIG_NAMES, { upward = true, path = start_dir, type = "file" })
    if found and found[1] then
      return vim.fn.fnamemodify(found[1], ":p"), "upward"
    end
  end

  local home = vim.fn.expand("~/.ansible.cfg")
  if uv.fs_stat(home) then
    return home, "home"
  end

  if uv.fs_stat("/etc/ansible/ansible.cfg") then
    return "/etc/ansible/ansible.cfg", "system"
  end

  return nil, "none"
end

---Settings coming from `ANSIBLE_*` environment variables, which outrank the
---config file.
---@return table
function M.env_settings()
  local settings = {}

  local password_file = vim.env.ANSIBLE_VAULT_PASSWORD_FILE
  if password_file and password_file ~= "" then
    settings.vault_password_file = vim.fn.expand(password_file)
  end

  local identity_list = vim.env.ANSIBLE_VAULT_IDENTITY_LIST
  if identity_list and identity_list ~= "" then
    local entries = {}
    for entry in identity_list:gmatch("[^,]+") do
      local item = entry:match("^%s*(.-)%s*$")
      if item ~= "" then
        table.insert(entries, resolve_vault_id(item, nil))
      end
    end
    if #entries > 0 then
      settings.vault_identity_list = entries
    end
  end

  for env_name, key in pairs({
    ANSIBLE_VAULT_IDENTITY = "vault_identity",
    ANSIBLE_VAULT_ENCRYPT_IDENTITY = "vault_encrypt_identity",
  }) do
    local value = vim.env[env_name]
    if value and value ~= "" then
      settings[key] = value
    end
  end

  for env_name, key in pairs({
    ANSIBLE_VAULT_ID_MATCH = "vault_id_match",
    ANSIBLE_ASK_VAULT_PASS = "ask_vault_pass",
  }) do
    local value = vim.env[env_name]
    if value and value ~= "" then
      settings[key] = truthy(value)
    end
  end

  return settings
end

---@class AnsibleVaultCfg
---@field cfg_path string|nil Config file Ansible would read
---@field cfg_source string Where the config came from
---@field cwd string|nil Directory `ansible-vault` should run in
---@field settings table Merged settings, environment winning over the file
---@field has_credentials boolean Whether Ansible can find a password on its own
---@field credential_source string|nil Which layer supplies them, when it does
---@field label string|nil Vault id label Ansible would encrypt with

---Resolve everything Ansible itself would resolve for a given file.
---@param file_path string|nil Buffer path; its directory starts the upward walk
---@return AnsibleVaultCfg
function M.resolve(file_path)
  -- Buffers with a scheme-style name, such as the `health://` report or the
  -- plugin's own `ansible-vault://` scratch buffers, do not expand to a real
  -- directory. Fall back to the working directory rather than searching upward
  -- from something that does not exist.
  local start_dir
  if file_path and file_path ~= "" then
    local candidate = vim.fn.fnamemodify(file_path, ":p:h")
    local stat = uv.fs_stat(candidate)
    if stat and stat.type == "directory" then
      start_dir = candidate
    end
  end
  start_dir = start_dir or vim.fn.getcwd()

  local cfg_path, cfg_source = find_config(start_dir)

  local file_settings = {}
  if cfg_path then
    local stat = uv.fs_stat(cfg_path)
    local key = cfg_path .. ":" .. (stat and stat.mtime and stat.mtime.sec or 0) .. ":" .. (stat and stat.size or 0)
    local cached = cache[key]
    if cached == nil then
      cached = parse_ini(cfg_path) or {}
      cache[key] = cached
    end
    file_settings = cached
  end

  local env_settings = M.env_settings()
  local settings = vim.tbl_extend("force", file_settings, env_settings)

  local identities = settings.vault_identity_list
  local has_password_file = type(settings.vault_password_file) == "string" and settings.vault_password_file ~= ""
  local has_identities = type(identities) == "table" and #identities > 0
  local has_credentials = has_password_file or has_identities

  local credential_source
  if has_credentials then
    local from_env = (has_password_file and env_settings.vault_password_file ~= nil)
      or (has_identities and env_settings.vault_identity_list ~= nil)
    credential_source = from_env and "ANSIBLE_* environment" or "ansible.cfg"
  end

  local label = settings.vault_encrypt_identity
  if (not label or label == "") and type(identities) == "table" and #identities == 1 then
    label = identities[1]:match("^([^@]+)@") or identities[1]
  end
  if not label or label == "" then
    label = nil
  end

  return {
    cfg_path = cfg_path,
    cfg_source = cfg_source,
    cwd = cfg_path and vim.fn.fnamemodify(cfg_path, ":h") or nil,
    settings = settings,
    has_credentials = has_credentials,
    credential_source = credential_source,
    label = label,
  }
end

return M
