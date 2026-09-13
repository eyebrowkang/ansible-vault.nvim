---The six commands: argument parsing, scope dispatch, registration and setup.
---
---`setup()` is the only thing this module exports. Commands are registered when
---the module loads, so they exist whether or not `setup()` was ever called, and
---registering again is harmless — which is what keeps a second `setup()` from
---disturbing an editing session that is already open.
---
---Scope is decided in `inline.lua` and is the same for every verb: an explicit
---`[range]` names one inline value, a vault header on line 1 means the whole file,
---and a cursor inside a `!vault` block names that block. `:VaultEncrypt` without a
---range is always the whole buffer — there is no state from an earlier command
---that can turn it into something else.
local M = {}

local ansible_cfg = require("ansible-vault.ansible_cfg")
local buffer = require("ansible-vault.buffer")
local config = require("ansible-vault.config")
local edit = require("ansible-vault.edit")
local file = require("ansible-vault.file")
local inline = require("ansible-vault.inline")

local is_nonempty_string = config.is_nonempty_string

--- Command arguments -------------------------------------------------------

---Split a command line into arguments, honouring quotes and backslash escapes.
---
---Neovim hands the argument list over as one string, so paths with spaces have to
---survive here or they cannot be passed at all:
---`:VaultEdit --vault-password-file "~/my secrets/pass"`.
---@param args string|nil
---@return string[]
local function parse_command_args(args)
  if not is_nonempty_string(args) then
    return {}
  end

  local function is_space(char)
    return char == " " or char == "\t"
  end

  local result = {}
  local i = 1
  local len = #args
  while i <= len do
    local c = args:sub(i, i)
    if is_space(c) then
      i = i + 1
    else
      local token = {}
      local quote = nil

      while i <= len do
        c = args:sub(i, i)

        if quote then
          if c == quote then
            quote = nil
            i = i + 1
          elseif c == "\\" and i < len then
            i = i + 1
            table.insert(token, args:sub(i, i))
            i = i + 1
          else
            table.insert(token, c)
            i = i + 1
          end
        elseif is_space(c) then
          break
        elseif c == "'" or c == '"' then
          quote = c
          i = i + 1
        elseif c == "\\" and i < len then
          i = i + 1
          table.insert(token, args:sub(i, i))
          i = i + 1
        else
          table.insert(token, c)
          i = i + 1
        end
      end

      table.insert(result, table.concat(token))
    end
  end
  return result
end

---Flags that name which credential opens a vault, spelled exactly as
---`ansible-vault` spells them.
local CREDENTIAL_FLAGS = {
  ["--vault-password-file"] = { key = "password_files", value = true, list = true },
  ["--vault-id"] = { key = "vault_ids", value = true, list = true },
  ["--ask-vault-password"] = { key = "ask_password", value = false },
}

---Which flags each command accepts.
---
---Per command rather than one shared list, so a flag that cannot mean anything is
---an error instead of a silent no-op. `--encrypt-vault-id` is the one that matters:
---on `rekey` it selects from a pool seeded with the *old* identities, so accepting
---it there would let a rekey report success and leave the file on its old
---password.
local FLAG_SETS = {
  read = CREDENTIAL_FLAGS,
  write = vim.tbl_extend("force", {}, CREDENTIAL_FLAGS, {
    ["--encrypt-vault-id"] = { key = "encrypt_vault_id", value = true },
  }),
  rekey = vim.tbl_extend("force", {}, CREDENTIAL_FLAGS, {
    ["--new-vault-password-file"] = { key = "new_password_file", value = true },
    ["--new-vault-id"] = { key = "new_vault_id", value = true },
  }),
}

---@param flags table
---@return string[]
local function flag_names(flags)
  local names = vim.tbl_keys(flags)
  table.sort(names)
  return names
end

---Turn command arguments into configuration overrides.
---
---Credential flags *replace* the configured credentials rather than adding to
---them, so `:VaultEdit --vault-id prod@~/.pass` uses exactly that identity. The
---`false` sentinel is what `config.effective` reads as "explicitly unset", which a
---`nil` could not express through `tbl_deep_extend`.
---@param args string[]
---@param command table
---@return table|nil parsed, string|nil err
local function parse_operation_options(args, command)
  local flags = FLAG_SETS[command.flags]
  local result = { overrides = {}, positionals = {} }
  local seen = {}

  local index = 1
  while index <= #args do
    local arg = args[index]
    local flag = flags[arg]

    if flag then
      local value = true
      if flag.value then
        value = args[index + 1]
        if value == nil or value:match("^%-%-") then
          return nil, string.format("missing value for %s", arg)
        end
        index = index + 2
      else
        index = index + 1
      end

      seen[flag.key] = true
      if flag.list then
        result.overrides[flag.key] = result.overrides[flag.key] or {}
        table.insert(result.overrides[flag.key], value)
      else
        result.overrides[flag.key] = value
      end
    elseif arg:match("^%-") then
      return nil, string.format("unknown argument: %s (accepted here: %s)", arg, table.concat(flag_names(flags), ", "))
    elseif command.positionals then
      table.insert(result.positionals, arg)
      index = index + 1
    else
      return nil, string.format("unexpected argument: %s", arg)
    end
  end

  if seen.ask_password and (seen.password_files or seen.vault_ids) then
    return nil, "--ask-vault-password cannot be combined with --vault-id or --vault-password-file"
  end

  if seen.new_vault_id and seen.new_password_file then
    return nil, "--new-vault-id and --new-vault-password-file are mutually exclusive"
  end

  -- Naming any credential on the command line means the configured ones do not
  -- apply at all; the same for a new identity on rekey.
  local EXCLUSIVE_GROUPS = {
    { "password_files", "vault_ids", "ask_password" },
    { "new_vault_id", "new_password_file" },
  }
  for _, group in ipairs(EXCLUSIVE_GROUPS) do
    local given = false
    for _, key in ipairs(group) do
      given = given or seen[key] == true
    end
    if given then
      for _, key in ipairs(group) do
        if not seen[key] then
          result.overrides[key] = false
        end
      end
    end
  end

  if command.positionals and #result.positionals > command.positionals then
    return nil, string.format("expected at most %d file name", command.positionals)
  end

  return result, nil
end

---@param arg_lead string
---@param command table
---@return string[]
local function complete_args(arg_lead, command)
  local candidates = flag_names(FLAG_SETS[command.flags])

  if command.positionals and not arg_lead:match("^%-") then
    vim.list_extend(candidates, vim.fn.getcompletion(arg_lead, "file"))
  end

  return vim.tbl_filter(function(candidate)
    return vim.startswith(candidate, arg_lead)
  end, candidates)
end

--- Verbs -------------------------------------------------------------------

---@param opts table
---@param want "ciphertext"|"plain"
---@return integer|nil target, table|nil scope
local function target_and_scope(opts, want)
  local target = vim.api.nvim_get_current_buf()
  if not buffer.is_valid(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return nil, nil
  end

  local scope, err = inline.resolve_scope(target, opts, want)
  if not scope then
    vim.notify(err, vim.log.levels.ERROR)
    return nil, nil
  end

  return target, scope
end

---@param opts table
local function vault_encrypt(opts)
  local target, scope = target_and_scope(opts, "plain")
  if not target then
    return
  end

  if scope.state == "ciphertext" then
    vim.notify(
      scope.scope == "file" and "Buffer is already encrypted" or "That value is already encrypted",
      vim.log.levels.WARN
    )
    return
  end

  if scope.scope == "file" then
    file.encrypt(target, opts)
  else
    inline.encrypt_region(target, scope.region, opts)
  end
end

---@param opts table
local function vault_decrypt(opts)
  local target, scope = target_and_scope(opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify("Nothing encrypted here to decrypt", vim.log.levels.WARN)
    return
  end

  if scope.scope == "file" then
    file.decrypt(target, opts)
  else
    inline.decrypt_region(target, scope.region, opts)
  end
end

---@param opts table
local function vault_view(opts)
  local target, scope = target_and_scope(opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify("Nothing encrypted here to view", vim.log.levels.WARN)
    return
  end

  if scope.scope == "file" then
    file.view(target, opts)
  else
    inline.view_region(target, scope.region, opts)
  end
end

---@param opts table
local function vault_edit(opts)
  local target, scope = target_and_scope(opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify("Nothing encrypted here to edit", vim.log.levels.WARN)
    return
  end

  if scope.scope == "file" then
    edit.edit_file(target, opts)
  else
    edit.edit_inline(target, scope.region, opts)
  end
end

---@param opts table
local function vault_rekey(opts)
  local target, scope = target_and_scope(opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify("Nothing encrypted here to rekey", vim.log.levels.WARN)
    return
  end

  if scope.scope == "file" then
    file.rekey(target, opts)
  else
    inline.rekey_region(target, scope.region, opts)
  end
end

--- Commands ----------------------------------------------------------------

---@type table[]
local COMMANDS = {
  {
    name = "VaultEncrypt",
    desc = "Encrypt the whole buffer, or the YAML value in [range]",
    flags = "write",
    range = true,
    run = vault_encrypt,
  },
  {
    name = "VaultDecrypt",
    desc = "Decrypt the buffer, or one inline !vault value, in place",
    flags = "read",
    range = true,
    run = vault_decrypt,
  },
  {
    name = "VaultView",
    desc = "Show decrypted content read-only, for the buffer or one inline value",
    flags = "read",
    range = true,
    run = vault_view,
  },
  {
    name = "VaultEdit",
    desc = "Edit a vault file, or one inline !vault value, in a protected buffer",
    flags = "write",
    range = true,
    run = vault_edit,
  },
  {
    name = "VaultCreate",
    desc = "Create a new Ansible Vault file",
    flags = "write",
    bang = true,
    positionals = 1,
    run = function(opts)
      edit.create(opts)
    end,
  },
  {
    name = "VaultRekey",
    desc = "Rekey the vault file, or one inline !vault value",
    flags = "rekey",
    range = true,
    run = vault_rekey,
  },
}

local version_warned = false

---The plugin tracks the current Neovim release only. Older versions are not
---worked around and are not tested; they may happen to work, but that is not a
---promise.
local function check_version()
  if version_warned or vim.fn.has("nvim-" .. config.MIN_NVIM_VERSION) == 1 then
    return
  end
  version_warned = true
  vim.notify(
    string.format(
      "ansible-vault.nvim supports Neovim %s and newer; older versions are untested",
      config.MIN_NVIM_VERSION
    ),
    vim.log.levels.WARN
  )
end

local registered = false

---Register every user command. Idempotent, and called when this module loads, so
---the commands exist without `setup()` and a second `setup()` changes nothing.
local function register_commands()
  if registered then
    return
  end
  registered = true

  for _, command in ipairs(COMMANDS) do
    vim.api.nvim_create_user_command(command.name, function(cmd_opts)
      check_version()

      local parsed, err = parse_operation_options(parse_command_args(cmd_opts.args), command)
      if not parsed then
        vim.notify(string.format(":%s: %s", command.name, err), vim.log.levels.ERROR)
        return
      end

      -- Scope and bang travel with the parsed options rather than being recovered
      -- from editor state later, which is what keeps a stale visual selection out
      -- of the decision.
      parsed.range = cmd_opts.range
      parsed.line1 = cmd_opts.line1
      parsed.line2 = cmd_opts.line2
      parsed.bang = cmd_opts.bang

      command.run(parsed)
    end, {
      nargs = "*",
      range = command.range or nil,
      bang = command.bang or nil,
      complete = function(arg_lead)
        return complete_args(arg_lead, command)
      end,
      desc = command.desc,
      force = true,
    })
  end
end

---Configure the plugin.
---
---Optional: the commands work with the defaults without it. Calling it again
---replaces the configuration and leaves any open vault buffer alone, because
---nothing an editing session depends on lives in the configuration.
---@param opts? AnsibleVaultConfig
function M.setup(opts)
  opts = opts or {}

  local errors = config.validate(opts)
  if #errors > 0 then
    vim.notify("ansible-vault.nvim setup: " .. table.concat(errors, "; "), vim.log.levels.ERROR)
    return
  end

  config.apply(opts)
  ansible_cfg.clear_cache()
  register_commands()
end

register_commands()

return M
