---@class AnsibleVaultConfig
---@field password_file? string Path to ansible-vault password file
---@field vault_id? string Vault ID to use, for example "prod@~/.vault_pass"
---@field vault_ids? string[] Vault IDs to use, for example { "dev@~/.dev-pass", "prod@~/.prod-pass" }
---@field encrypt_vault_id? string Vault ID label to use for encryption
---@field rekey_password_file? string New vault password file for VaultRekey
---@field rekey_vault_id? string New vault ID for VaultRekey, for example "prod@~/.ansible/new-pass"
---@field auto_detect? boolean Auto detect vault encrypted files (default: true)
---@field auto_edit? boolean Automatically open encrypted files with VaultEdit (default: false)
---@field password_cache_ttl? number Cache interactive passwords in memory for N seconds (default: 0)
---@field timeout_ms? number ansible-vault job timeout in milliseconds (default: 30000, set 0 to disable)
---@field notify_success? boolean Show success/info notifications (default: true)
---@field conda_env? string Conda environment name where ansible-vault is installed
---@field ansible_vault_path? string Custom path to ansible-vault executable
---@field debug? boolean Enable debug logging (default: false)

local ansible_cfg = require("ansible-vault.ansible_cfg")
local credentials = require("ansible-vault.credentials")
local secure = require("ansible-vault.secure")
local yaml = require("ansible-vault.yaml")

local M = {}

---Minimum supported Neovim version.
---
---The plugin tracks the current Neovim release only. Older versions are not
---worked around and are not tested; they may happen to work, but that is not a
---promise. Keeping a single target is what keeps this maintainable.
M.MIN_NVIM_VERSION = "0.12"

local uv = vim.uv
local AUGROUP = "AnsibleVault"
local DEFAULT_FILE_MODE = 384 -- 0600
local NAMESPACE = vim.api.nvim_create_namespace("ansible-vault")
local parse_vault_from_yaml
local has_rekey_target
local write_plaintext_buffer
local restore_inline_regions
local leave_plaintext_mode
local remember_header

---@type AnsibleVaultConfig
local DEFAULT_CONFIG = {
  password_file = nil,
  vault_id = nil,
  vault_ids = nil,
  encrypt_vault_id = nil,
  rekey_password_file = nil,
  rekey_vault_id = nil,
  auto_detect = true,
  auto_edit = false,
  password_cache_ttl = 0,
  timeout_ms = 30000,
  notify_success = true,
  conda_env = nil,
  ansible_vault_path = nil,
  debug = false,
}

---@type AnsibleVaultConfig
M.config = vim.deepcopy(DEFAULT_CONFIG)

---Debug log helper.
---
---Only ever goes to `vim.notify`. Printing to stdout as well would put whatever
---is logged into the terminal scrollback, where it outlives the session.
---@param msg string
---@param ... any
local function debug_log(msg, ...)
  if M.config.debug then
    vim.notify("[ansible-vault DEBUG] " .. string.format(msg, ...), vim.log.levels.DEBUG)
  end
end

---Render an argv for logging with credential values replaced.
---@param argv string[]
---@return string
local function redact_argv(argv)
  local parts = {}
  local redact_next = false
  for _, arg in ipairs(argv) do
    if redact_next then
      table.insert(parts, "<redacted>")
      redact_next = false
    else
      table.insert(parts, arg)
      redact_next = arg:match("^%-%-vault%-password%-file$") ~= nil
        or arg:match("^%-%-vault%-pass%-file$") ~= nil
        or arg:match("^%-%-vault%-id$") ~= nil
        or arg:match("^%-%-new%-vault%-password%-file$") ~= nil
        or arg:match("^%-%-new%-vault%-id$") ~= nil
    end
  end
  return table.concat(parts, " ")
end

---@param value any
---@return boolean
local function is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

---Merge per-command overrides over the configured defaults.
---
---`vault_ids` is replaced wholesale rather than merged: `tbl_deep_extend` merges
---list-like tables element by element, so a single `--vault-id x` against a
---configured list would leave the remaining configured entries in place.
---@param opts? table
---@return table
local function effective_config(opts)
  local overrides = opts and (opts.overrides or opts) or {}
  local config = vim.tbl_deep_extend("force", M.config, overrides)
  if overrides.vault_ids ~= nil then
    config.vault_ids = overrides.vault_ids
  end
  return config
end

---@param message string
---@param level integer
---@param opts? table
local function notify(message, level, opts)
  local config = effective_config(opts)
  if level == vim.log.levels.INFO and config.notify_success == false then
    return
  end
  vim.notify(message, level)
end

---Announce a completed operation on the one `User` pattern the plugin emits.
---
---A single pattern with the operation in `data` is what a listener actually
---wants: one autocmd can act on everything, and filtering on `op`/`scope` is a
---comparison rather than a dozen registrations to keep in sync.
---@param op "encrypt"|"decrypt"|"view"|"edit"|"save"|"rekey"|"create"
---@param scope "file"|"inline"
---@param data? table
local function emit_event(op, scope, data)
  local payload = vim.tbl_deep_extend("force", { op = op, scope = scope }, data or {})
  pcall(vim.api.nvim_exec_autocmds, "User", {
    pattern = "AnsibleVaultOperation",
    data = payload,
  })
end

---@param opts? table
---@return integer|nil
local function get_timeout_ms(opts)
  local timeout = effective_config(opts).timeout_ms
  if type(timeout) == "number" and timeout > 0 then
    return math.floor(timeout)
  end
  return nil
end

local clear_password_cache = credentials.clear_password_cache
local expand_path = credentials.expand_path
local expand_vault_id = credentials.expand_vault_id

---The argv prefix that runs `ansible-vault`, honouring `ansible_vault_path`.
---
---Public because `:checkhealth` reports the executable it would actually use, and
---resolving that itself would be a second implementation that could disagree.
---@param opts? table
---@return string[]
function M.executable_argv(opts)
  local config = effective_config(opts)
  local executable = "ansible-vault"
  if is_nonempty_string(config.ansible_vault_path) then
    executable = expand_path(config.ansible_vault_path)
  end

  if is_nonempty_string(config.conda_env) then
    return { "conda", "run", "-n", config.conda_env, executable }
  end

  return { executable }
end

---@param action string
---@param args string[]
---@param target? string|false
---@param opts? table
---@return string[]
local function build_vault_argv(action, args, target, opts)
  local argv = M.executable_argv(opts)
  table.insert(argv, action)
  for _, arg in ipairs(args or {}) do
    table.insert(argv, tostring(arg))
  end
  if target == nil then
    target = "-"
  end
  if target ~= false then
    table.insert(argv, tostring(target))
  end
  return argv
end

---@param output string
---@return string[]
local function output_to_lines(output)
  if output == "" then
    return { "" }
  end
  return vim.split(output, "\n", { plain = true })
end

---Context describing which file an operation applies to, so credentials and the
---encryption label can be resolved the way Ansible would resolve them there.
---@param buf? integer
---@return { file_path?: string, header_label?: string }
local function buffer_context(buf)
  local context = {}
  if buf and vim.api.nvim_buf_is_valid(buf) then
    -- Read the header while the buffer still holds ciphertext. Once it has been
    -- decrypted there is nothing left to recover the vault id label from, and
    -- re-encrypting without it silently rewrites the file as format 1.1.
    remember_header(buf)

    local name = vim.api.nvim_buf_get_name(buf)
    if name ~= "" then
      context.file_path = name
    end
    context.header_label = vim.b[buf].ansible_vault_label
  end
  if not context.file_path then
    context.file_path = vim.api.nvim_buf_get_name(vim.api.nvim_get_current_buf())
    if context.file_path == "" then
      context.file_path = nil
    end
  end
  return context
end

---Resolve credentials for an operation.
---@param callback fun(creds: AnsibleVaultCredentials|nil)
---@param opts? table
---@param context? table
local function get_credentials(callback, opts, context)
  credentials.resolve(effective_config(opts), context or {}, callback)
end

---Append `--encrypt-vault-id` when a specific identity must be named: because the
---user configured one, because the file's own 1.2 header records one that would
---otherwise be lost, or because Ansible's config contributes a second identity
---and leaving the choice implicit is an error.
---@param args string[]
---@param opts? table
---@param creds? AnsibleVaultCredentials
---@param context? table
---@return string[]
local function with_encrypt_vault_id(args, opts, creds, context)
  local config = effective_config(opts)
  local result = vim.deepcopy(args or {})

  local label
  if creds and creds.plan then
    label = credentials.encrypt_label(config, creds.plan, context)
  elseif is_nonempty_string(config.encrypt_vault_id) then
    label = config.encrypt_vault_id
  end

  if is_nonempty_string(label) then
    table.insert(result, "--encrypt-vault-id")
    table.insert(result, label)
  end
  return result
end

---@param extra_args string[]|nil
---@param opts? table
---@return string[]
local function with_rekey_target_args(extra_args, opts)
  local config = effective_config(opts)
  local args = vim.deepcopy(extra_args or {})
  if has_rekey_target(args) then
    return args
  end

  if is_nonempty_string(config.rekey_password_file) then
    table.insert(args, "--new-vault-password-file")
    table.insert(args, expand_path(config.rekey_password_file))
  elseif is_nonempty_string(config.rekey_vault_id) then
    table.insert(args, "--new-vault-id")
    table.insert(args, expand_vault_id(config.rekey_vault_id))
  end

  return args
end

---@param args string[]
---@return boolean
has_rekey_target = function(args)
  for _, arg in ipairs(args or {}) do
    if arg == "--new-vault-password-file" or arg == "--new-vault-id" then
      return true
    end
  end
  return false
end

---Describe a failed run without echoing the process output.
---
---`ansible-vault decrypt` can exit non-zero after having already written
---plaintext to stdout, so stdout must never end up in a message that lands in
---`:messages` or a notification backend's log.
---@param action string
---@param exit_code integer
---@param stderr string
---@return string
local function failure_message(action, exit_code, stderr)
  if stderr ~= "" then
    return stderr
  end
  return string.format("ansible-vault %s exited with status %d", action, exit_code)
end

---Spawn `ansible-vault` and hand the result to `callback`.
---
---`vim.system` enforces the timeout itself and reports exit code 124 when it
---fires, so there is no timer to arm, cancel or leak. It also merges `env` into
---the inherited environment rather than replacing it, which is what lets the
---password be passed through `ANSIBLE_VAULT_NVIM_PASSWORD` without stripping
---`PATH` from the child.
---@param action string
---@param args string[]
---@param opts table|nil
---@param creds AnsibleVaultCredentials|nil
---@param stdin string|nil Content to pipe in, or nil when operating on a file
---@param file string|nil File to operate on, or nil when piping stdin
---@param callback fun(success: boolean, output: string)
local function spawn_vault(action, args, opts, creds, stdin, file, callback)
  local argv = build_vault_argv(action, args or {}, file or "-", opts)
  debug_log("running: %s", redact_argv(argv))

  local timeout = get_timeout_ms(opts)
  local system_opts = {
    cwd = creds and creds.cwd or nil,
    env = creds and creds.env or nil,
    timeout = timeout,
    stdin = stdin,
  }

  -- Deliberately not `text = true`: that would normalize CRLF in the output,
  -- rewriting the line endings of whatever was decrypted.
  local ok, err = pcall(vim.system, argv, system_opts, function(result)
    vim.schedule(function()
      if result.code == 0 then
        callback(true, result.stdout or "")
      elseif result.code == 124 then
        callback(false, string.format("ansible-vault %s timed out after %dms", action, timeout or 0))
      else
        callback(false, failure_message(action, result.code, result.stderr or ""))
      end
    end)
  end)

  if not ok then
    callback(false, "Failed to start ansible-vault: " .. tostring(err))
  end
end

---Run ansible-vault over buffer content.
---@param action string The vault action (encrypt, decrypt, encrypt_string)
---@param input string Input content
---@param args string[] Additional arguments
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
---@param creds? AnsibleVaultCredentials Supplies the child cwd and environment
local function run_vault(action, input, args, callback, opts, creds)
  spawn_vault(action, args, opts, creds, input, nil, callback)
end

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

---@param args string[]|nil
---@param opts? table
---@return table
local function parse_operation_options(args, opts)
  local result = {
    overrides = {},
    positionals = {},
    rekey_args = {},
  }

  local index = 1
  while index <= #(args or {}) do
    local arg = args[index]
    local next_arg = args[index + 1]

    if (arg == "--vault-password-file" or arg == "--vault-pass-file" or arg == "--password-file") and next_arg then
      result.overrides.password_file = next_arg
      result.overrides.vault_id = false
      result.overrides.vault_ids = false
      index = index + 2
    elseif arg == "--vault-id" and next_arg then
      result.overrides.password_file = false
      result.overrides.vault_ids = result.overrides.vault_ids or {}
      table.insert(result.overrides.vault_ids, next_arg)
      index = index + 2
    elseif arg == "--encrypt-vault-id" and next_arg then
      result.overrides.encrypt_vault_id = next_arg
      index = index + 2
    elseif arg == "--new-vault-password-file" and next_arg then
      result.overrides.rekey_password_file = next_arg
      vim.list_extend(result.rekey_args, { arg, next_arg })
      index = index + 2
    elseif arg == "--new-vault-id" and next_arg then
      result.overrides.rekey_vault_id = next_arg
      vim.list_extend(result.rekey_args, { arg, next_arg })
      index = index + 2
    elseif opts and opts.label_shortcut and not arg:match("^%-") and not result.overrides.encrypt_vault_id then
      result.overrides.encrypt_vault_id = arg
      index = index + 1
    else
      table.insert(result.positionals, arg)
      index = index + 1
    end
  end

  return result
end

---@param arg_lead string
---@param include_rekey? boolean
---@param include_labels? boolean
---@return string[]
local function complete_operation_args(arg_lead, include_rekey, include_labels)
  local candidates = {
    "--vault-id",
    "--vault-password-file",
    "--password-file",
    "--encrypt-vault-id",
  }

  if include_rekey then
    table.insert(candidates, "--new-vault-password-file")
    table.insert(candidates, "--new-vault-id")
  end

  local labels = {}
  if is_nonempty_string(M.config.vault_id) then
    local label = M.config.vault_id:match("^([^@]+)@")
    if label then
      table.insert(labels, label)
    end
  end
  if type(M.config.vault_ids) == "table" then
    for _, vault_id in ipairs(M.config.vault_ids) do
      local label = type(vault_id) == "string" and vault_id:match("^([^@]+)@")
      if label then
        table.insert(labels, label)
      end
    end
  end
  if include_labels then
    vim.list_extend(candidates, labels)
  end

  return vim.tbl_filter(function(candidate)
    return vim.startswith(candidate, arg_lead)
  end, candidates)
end

---Run ansible-vault against a file path.
---@param action string
---@param file_path string
---@param args string[]
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
---@param creds? AnsibleVaultCredentials
local function run_vault_file(action, file_path, args, callback, opts, creds)
  spawn_vault(action, args, opts, creds, nil, file_path, callback)
end

---@param buf? integer
---@return integer
local function normalize_buf(buf)
  return buf or vim.api.nvim_get_current_buf()
end

---@param buf integer
---@return boolean
local function is_valid_buf(buf)
  return vim.api.nvim_buf_is_valid(buf)
end

---@param buf integer
---@return integer
local function changedtick(buf)
  return vim.b[buf].changedtick or 0
end

---@param buf integer
---@return string
local function buffer_content(buf)
  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  return table.concat(lines, "\n")
end

---@param cleanup? fun()
local function run_cleanup(cleanup)
  if cleanup then
    cleanup()
  end
end

---@param buf integer
---@param operation string
---@return boolean
local function start_buffer_operation(buf, operation)
  if vim.b[buf].ansible_vault_pending then
    vim.notify(
      string.format("Vault operation already running: %s", vim.b[buf].ansible_vault_pending),
      vim.log.levels.WARN
    )
    return false
  end

  vim.b[buf].ansible_vault_pending = operation
  return true
end

---@param buf integer
---@param operation string
local function finish_buffer_operation(buf, operation)
  if is_valid_buf(buf) and vim.b[buf].ansible_vault_pending == operation then
    vim.b[buf].ansible_vault_pending = nil
  end
end

---@param buf integer
---@param expected_changedtick integer
---@param output string
---@param success_message string
---@param opts? table
---@return boolean
local function replace_buffer_lines(buf, expected_changedtick, output, success_message, opts)
  if not is_valid_buf(buf) then
    vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
    return false
  end

  if changedtick(buf) ~= expected_changedtick then
    vim.notify("Vault operation finished, but the buffer changed; result was not applied", vim.log.levels.ERROR)
    return false
  end

  local lines = output_to_lines(output)
  local becomes_plaintext = not M.is_encrypted(lines)

  local ok, err
  if becomes_plaintext then
    -- Harden first: resetting 'swapfile' deletes any existing swap file, and
    -- doing it before the plaintext lands is what keeps it off disk.
    ok, err = secure.set_plaintext_lines(buf, lines)
  else
    ok, err = secure.with_cleared_undo(buf, function()
      vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    end)
  end

  if not ok then
    vim.notify("Failed to update buffer: " .. tostring(err), vim.log.levels.ERROR)
    return false
  end

  remember_header(buf, lines)
  notify(success_message, vim.log.levels.INFO, opts)
  return true
end

---@param output string
---@param title string
---@param filetype? string
local function open_output_window(output, title, filetype)
  -- Explicitly hardened rather than relying on the implicit scratch defaults;
  -- this window shows decrypted content.
  local buf = secure.create_buffer(false, true)
  local lines = output_to_lines(output)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].bufhidden = "wipe"
  vim.bo[buf].filetype = filetype or ""
  vim.bo[buf].modifiable = false

  local max_line_width = 0
  for _, line in ipairs(lines) do
    max_line_width = math.max(max_line_width, vim.api.nvim_strwidth(line))
  end

  local available_width = math.max(1, vim.o.columns - 4)
  local available_height = math.max(1, vim.o.lines - 4)
  local width = math.min(math.max(max_line_width + 2, 40), available_width)
  local height = math.min(math.max(#lines, 1), available_height)

  local win = vim.api.nvim_open_win(buf, true, {
    relative = "editor",
    width = width,
    height = height,
    col = math.max(0, math.floor((vim.o.columns - width) / 2)),
    row = math.max(0, math.floor((vim.o.lines - height) / 2)),
    style = "minimal",
    border = "rounded",
    title = title,
    title_pos = "center",
  })

  local close_window = function()
    if vim.api.nvim_win_is_valid(win) then
      vim.api.nvim_win_close(win, true)
    end
  end

  vim.keymap.set("n", "q", close_window, { buffer = buf, desc = "Close vault view" })
  vim.keymap.set("n", "<Esc>", close_window, { buffer = buf, desc = "Close vault view" })
end

---@param content string|string[]
---@return string
local function first_line_of(content)
  if type(content) == "table" then
    return content[1] or ""
  end
  return content:match("^[^\n]*") or ""
end

---Parse the `$ANSIBLE_VAULT` header of some content.
---@param content string|string[]
---@return AnsibleVaultHeader|nil
function M.parse_header(content)
  return yaml.parse_header(first_line_of(content))
end

---Check if content is vault encrypted.
---@param content string|string[]
---@return boolean
function M.is_encrypted(content)
  return M.parse_header(content) ~= nil
end

---Check if buffer is vault encrypted.
---@param buf? integer
---@return boolean
function M.is_buffer_encrypted(buf)
  local target = normalize_buf(buf)
  if not is_valid_buf(target) then
    return false
  end
  local lines = vim.api.nvim_buf_get_lines(target, 0, 1, false)
  return M.is_encrypted(lines)
end

---Record the vault format version and id label a buffer's ciphertext carries, so
---re-encrypting can preserve them instead of silently downgrading to format 1.1.
---@param buf integer
---@param content? string|string[]
remember_header = function(buf, content)
  if not is_valid_buf(buf) then
    return
  end

  local header = M.parse_header(content or vim.api.nvim_buf_get_lines(buf, 0, 1, false))
  if header then
    vim.b[buf].ansible_vault_version = header.version
    vim.b[buf].ansible_vault_label = header.label
  end
end

--- Plaintext editing mode -------------------------------------------------
---
---Once a buffer holds decrypted content, every write has to go back through this
---plugin. Setting 'buftype' to "acwrite" is what guarantees that: Neovim then
---routes `:w`, `:w {file}` and `:x` alike to our BufWriteCmd and never runs its
---own write path, so no plaintext backup file is made, no undo file is written,
---and a reflexive `:w` cannot put secrets on disk.
---
---Two shapes exist. "file" means the whole buffer is plaintext, so `:w` encrypts
---all of it and the buffer stays decrypted for further editing. "inline" means
---only the tracked `!vault` values were decrypted, so `:w` folds them back into
---the buffer and the file is written as ordinary YAML.

---@param buf integer
---@return boolean
local function is_plaintext_mode(buf)
  return is_valid_buf(buf) and vim.b[buf].ansible_vault_plaintext ~= nil
end

---@param buf integer
---@param mode "file"|"inline"
---@param opts? table
local function enter_plaintext_mode(buf, mode, opts)
  if not is_valid_buf(buf) then
    return
  end

  secure.protect(buf)

  if is_plaintext_mode(buf) then
    return
  end

  -- Unnamed buffers get the same treatment: `:w some-file` on one would
  -- otherwise write the plaintext straight out. BufWriteCmd receives the
  -- requested path, so it encrypts to wherever the user asked.
  vim.b[buf].ansible_vault_plaintext = mode
  vim.bo[buf].buftype = "acwrite"

  vim.b[buf].ansible_vault_write_autocmd = vim.api.nvim_create_autocmd("BufWriteCmd", {
    buffer = buf,
    desc = "Encrypt Ansible Vault content before writing",
    callback = function(event)
      write_plaintext_buffer(event.buf, event.file, opts)
    end,
  })

  notify(
    mode == "file" and "Buffer is decrypted. :w re-encrypts before writing."
      or "Value is decrypted. :w restores the vault block before writing.",
    vim.log.levels.INFO,
    opts
  )
end

---Return the buffer to its normal, ciphertext-backed behaviour.
---@param buf integer
leave_plaintext_mode = function(buf)
  if not is_valid_buf(buf) then
    return
  end

  vim.b[buf].ansible_vault_plaintext = nil
  vim.b[buf].ansible_vault_inline = nil
  pcall(vim.api.nvim_buf_clear_namespace, buf, NAMESPACE, 0, -1)

  -- Remove only our own handler; other plugins may have their own BufWriteCmd
  -- registered against this buffer.
  local autocmd_id = vim.b[buf].ansible_vault_write_autocmd
  if autocmd_id then
    pcall(vim.api.nvim_del_autocmd, autocmd_id)
    vim.b[buf].ansible_vault_write_autocmd = nil
  end

  secure.restore(buf)
end

---Encrypt current buffer.
---@param buf? integer
---@param opts? table
function M.encrypt(buf, opts)
  local target = normalize_buf(buf)
  if not is_valid_buf(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  if M.is_buffer_encrypted(target) then
    vim.notify("Buffer is already encrypted", vim.log.levels.WARN)
    return
  end

  local context = buffer_context(target)

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if not start_buffer_operation(target, "encrypt") then
      run_cleanup(creds.cleanup)
      return
    end

    local tick = changedtick(target)
    local content = buffer_content(target)
    local args = with_encrypt_vault_id(creds.args, opts, creds, context)

    run_vault("encrypt", content, args, function(success, output)
      run_cleanup(creds.cleanup)
      finish_buffer_operation(target, "encrypt")

      if success then
        if replace_buffer_lines(target, tick, output, "Buffer encrypted successfully", opts) then
          leave_plaintext_mode(target)
          emit_event("encrypt", "file", { buf = target })
        end
      else
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---Decrypt current buffer.
---@param buf? integer
---@param opts? table
function M.decrypt(buf, opts)
  local target = normalize_buf(buf)
  if not is_valid_buf(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  if not M.is_buffer_encrypted(target) then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  local context = buffer_context(target)

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if not start_buffer_operation(target, "decrypt") then
      run_cleanup(creds.cleanup)
      return
    end

    local tick = changedtick(target)
    local content = buffer_content(target)

    run_vault("decrypt", content, creds.args, function(success, output)
      run_cleanup(creds.cleanup)
      finish_buffer_operation(target, "decrypt")

      if success then
        if replace_buffer_lines(target, tick, output, "Buffer decrypted successfully", opts) then
          enter_plaintext_mode(target, "file", opts)
          emit_event("decrypt", "file", { buf = target })
        end
      else
        clear_password_cache()
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---View encrypted buffer in a floating window.
---@param buf? integer
---@param opts? table
function M.view(buf, opts)
  local target = normalize_buf(buf)
  if not is_valid_buf(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  if not M.is_buffer_encrypted(target) then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  local filetype = vim.bo[target].filetype
  local context = buffer_context(target)

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    run_vault("decrypt", buffer_content(target), creds.args, function(success, output)
      run_cleanup(creds.cleanup)

      if success then
        open_output_window(output, " Vault View (read-only) ", filetype)
        emit_event("view", "file", { buf = target })
      else
        clear_password_cache()
        vim.notify("View failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---@class AnsibleVaultSelection
---@field start_row integer
---@field start_col integer
---@field end_row integer
---@field end_col integer
---@field lines string[]
---@field linewise boolean
---@field blockwise boolean

---@param buf integer
---@param range_opts? table
---@return AnsibleVaultSelection|nil
local function get_selection(buf, range_opts)
  local start_row, start_col, end_row, end_col
  local range_linewise = false

  local has_range = range_opts and range_opts.range and range_opts.range > 0
  if has_range then
    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")
    local mark_start_row = start_pos[2]
    local mark_end_row = end_pos[2]
    local marks_match = mark_start_row == range_opts.line1 and mark_end_row == range_opts.line2
    if marks_match then
      start_row = mark_start_row
      start_col = start_pos[3]
      end_row = mark_end_row
      end_col = end_pos[3]
    else
      start_row = range_opts.line1
      end_row = range_opts.line2
      start_col = 1
      local last_line = vim.api.nvim_buf_get_lines(buf, end_row - 1, end_row, false)[1] or ""
      end_col = #last_line
      range_linewise = true
    end
  else
    local current_mode = vim.api.nvim_get_mode().mode
    local in_visual = current_mode == "v" or current_mode == "V" or current_mode == "\22"
    if in_visual then
      local v_start = vim.fn.getpos("v")
      local v_end = vim.fn.getpos(".")
      if v_start[2] > 0 and v_end[2] > 0 then
        start_row = v_start[2]
        start_col = v_start[3]
        end_row = v_end[2]
        end_col = v_end[3]
        range_linewise = current_mode == "V"
      end
    end

    if not start_row then
      local start_pos = vim.fn.getpos("'<")
      local end_pos = vim.fn.getpos("'>")
      start_row = start_pos[2]
      start_col = start_pos[3]
      end_row = end_pos[2]
      end_col = end_pos[3]
    end

    if start_row == 0 or end_row == 0 then
      if not range_opts or not range_opts.line1 or not range_opts.line2 then
        return nil
      end
      start_row = range_opts.line1
      end_row = range_opts.line2
      start_col = 1
      local last_line = vim.api.nvim_buf_get_lines(buf, end_row - 1, end_row, false)[1] or ""
      end_col = #last_line
      range_linewise = true
    end
  end

  if start_row > end_row or (start_row == end_row and start_col > end_col) then
    start_row, end_row = end_row, start_row
    start_col, end_col = end_col, start_col
  end

  local line_count = vim.api.nvim_buf_line_count(buf)
  start_row = math.max(1, math.min(start_row, line_count))
  end_row = math.max(1, math.min(end_row, line_count))
  start_col = math.max(1, start_col)
  end_col = math.max(0, end_col)

  local visual_mode = vim.fn.visualmode()
  local linewise = range_linewise or visual_mode == "V"
  local blockwise = visual_mode == "\22"
  local lines

  if blockwise then
    lines = {}
    for row = start_row, end_row do
      local line_text = vim.api.nvim_buf_get_text(buf, row - 1, start_col - 1, row - 1, end_col, {})
      table.insert(lines, line_text[1] or "")
    end
  elseif not linewise then
    local lines_from_text = vim.api.nvim_buf_get_text(buf, start_row - 1, start_col - 1, end_row - 1, end_col, {})
    if not lines_from_text or #lines_from_text == 0 then
      local fallback = vim.api.nvim_buf_get_lines(buf, start_row - 1, end_row, false)
      if #fallback == 0 then
        return nil
      end
      lines = fallback
    else
      lines = lines_from_text
    end
  else
    lines = vim.api.nvim_buf_get_lines(buf, start_row - 1, end_row, false)
    if #lines == 0 then
      return nil
    end
    start_col = 1
    end_col = #lines[#lines]
  end

  return {
    start_row = start_row - 1,
    start_col = start_col - 1,
    end_row = end_row - 1,
    end_col = end_col,
    lines = lines,
    linewise = linewise,
    blockwise = blockwise,
  }
end

---@param buf integer
---@param start_row integer 1-based
---@param end_row integer 1-based
---@return AnsibleVaultSelection|nil
local function get_line_selection(buf, start_row, end_row)
  local line_count = vim.api.nvim_buf_line_count(buf)
  start_row = math.max(1, math.min(start_row, line_count))
  end_row = math.max(1, math.min(end_row, line_count))

  if start_row > end_row then
    start_row, end_row = end_row, start_row
  end

  local lines = vim.api.nvim_buf_get_lines(buf, start_row - 1, end_row, false)
  if #lines == 0 then
    return nil
  end

  return {
    start_row = start_row - 1,
    start_col = 0,
    end_row = end_row - 1,
    end_col = #lines[#lines],
    lines = lines,
    linewise = true,
  }
end

local extract_yaml_key_value = yaml.extract_key_value

---@param buf integer
---@return AnsibleVaultSelection|nil
local function get_plain_yaml_value_under_cursor(buf)
  local row = vim.api.nvim_win_get_cursor(0)[1]
  local line = vim.api.nvim_buf_get_lines(buf, row - 1, row, false)[1] or ""
  local _, key, value = extract_yaml_key_value(line)
  if not key or not value or value == "" then
    return nil
  end
  return get_line_selection(buf, row, row)
end

---@param buf integer
---@return AnsibleVaultSelection|nil
local function find_vault_block_under_cursor(buf)
  local cursor_row = vim.api.nvim_win_get_cursor(0)[1]
  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)

  local start_row, end_row = yaml.find_block(lines, cursor_row)
  if not start_row then
    return nil
  end

  local selection = get_line_selection(buf, start_row, end_row)
  if not selection then
    return nil
  end

  if not parse_vault_from_yaml(table.concat(selection.lines, "\n")) then
    return nil
  end

  return selection
end

---@param text string
---@return string
local function escape_pattern(text)
  local escaped = text:gsub("([^%w])", "%%%1")
  return escaped
end

---@param buf integer
---@param selection AnsibleVaultSelection
---@return table
local function build_encrypt_string_plan(buf, selection)
  local plan = {
    content = table.concat(selection.lines, "\n"),
    name = "encrypted_string",
    mode = "full_output",
    indent = "",
    start_row = selection.start_row,
    start_col = selection.start_col,
    end_row = selection.end_row,
    end_col = selection.end_col,
  }

  if selection.start_row ~= selection.end_row then
    return plan
  end

  local full_line = vim.api.nvim_buf_get_lines(buf, selection.start_row, selection.start_row + 1, false)[1] or ""
  local is_full_line = selection.start_col == 0 and selection.end_col >= #full_line

  if is_full_line then
    local indent, key, value = extract_yaml_key_value(full_line)
    if key and value and value ~= "" then
      plan.content = value
      plan.name = key
      plan.mode = "full_line"
      plan.indent = indent or ""
    end
    return plan
  end

  -- A partial selection that starts exactly where the value begins: keep the key
  -- and replace only the value.
  local key_line = yaml.parse_key_line(full_line)
  if key_line and key_line.value_col == selection.start_col then
    plan.name = key_line.key
    plan.mode = "value_only"
    plan.indent = key_line.indent
  end

  return plan
end

---@param output string
---@param plan table
---@return string[]
local function format_encrypt_string_output(output, plan)
  local lines = output_to_lines(output)

  -- ansible-vault terminates its output with a newline; splicing that in as-is
  -- would leave a stray blank line behind in the buffer.
  while #lines > 1 and lines[#lines] == "" do
    table.remove(lines, #lines)
  end

  if plan.mode == "value_only" then
    local key_pattern = "^%s*" .. escape_pattern(plan.name) .. ":%s*(.*)$"
    local first_value = lines[1] and lines[1]:match(key_pattern)
    if first_value then
      lines[1] = first_value
    end
    -- The first line is spliced in at the value column, but the ciphertext lines
    -- below it are still at ansible-vault's fixed indentation. Shift them to sit
    -- under the key, matching what full-line encryption produces.
    if plan.indent ~= "" then
      for i = 2, #lines do
        lines[i] = plan.indent .. lines[i]
      end
    end
  elseif plan.mode == "full_line" and plan.indent ~= "" then
    for i, line in ipairs(lines) do
      lines[i] = plan.indent .. line
    end
  end

  return lines
end

---@param buf integer
---@param selection AnsibleVaultSelection
---@param replacement string[]
local function replace_selection_text(buf, selection, replacement)
  if not selection.blockwise then
    return pcall(
      vim.api.nvim_buf_set_text,
      buf,
      selection.start_row,
      selection.start_col,
      selection.end_row,
      selection.end_col,
      replacement
    )
  end

  local selected_row_count = selection.end_row - selection.start_row + 1
  local original_lines = vim.api.nvim_buf_get_lines(buf, selection.start_row, selection.end_row + 1, false)
  local new_lines = {}
  local line_count = math.max(selected_row_count, #replacement)

  for i = 1, line_count do
    local original = original_lines[i]
    if original then
      local prefix = original:sub(1, selection.start_col)
      local suffix = original:sub(selection.end_col + 1)
      table.insert(new_lines, prefix .. (replacement[i] or "") .. suffix)
    else
      table.insert(new_lines, replacement[i] or "")
    end
  end

  return pcall(vim.api.nvim_buf_set_lines, buf, selection.start_row, selection.end_row + 1, false, new_lines)
end

---@param buf integer
---@param selection AnsibleVaultSelection
---@param opts? table
local function encrypt_string_selection(buf, selection, opts)
  if not selection or #selection.lines == 0 then
    vim.notify("No text selected", vim.log.levels.WARN)
    return
  end

  local plan = build_encrypt_string_plan(buf, selection)
  local planned_tick = changedtick(buf)
  local context = buffer_context(buf)

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not is_valid_buf(buf) then
      run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if changedtick(buf) ~= planned_tick then
      run_cleanup(creds.cleanup)
      vim.notify("Buffer changed before encryption started; result was not applied", vim.log.levels.ERROR)
      return
    end

    if not start_buffer_operation(buf, "encrypt_string") then
      run_cleanup(creds.cleanup)
      return
    end

    local full_args = with_encrypt_vault_id(creds.args, opts, creds, context)
    table.insert(full_args, "--stdin-name")
    table.insert(full_args, plan.name)

    run_vault("encrypt_string", plan.content, full_args, function(success, output)
      run_cleanup(creds.cleanup)
      finish_buffer_operation(buf, "encrypt_string")

      if not success then
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if not is_valid_buf(buf) then
        vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if changedtick(buf) ~= planned_tick then
        vim.notify("Vault operation finished, but the buffer changed; result was not applied", vim.log.levels.ERROR)
        return
      end

      local ok, err = replace_selection_text(buf, selection, format_encrypt_string_output(output, plan))

      if ok then
        notify("String encrypted successfully", vim.log.levels.INFO, opts)
        emit_event("encrypt", "inline", { buf = buf, name = plan.name })
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---Encrypt selected text.
---@param range_opts? table
---@param opts? table
function M.encrypt_string(range_opts, opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_selection(target, range_opts)

  encrypt_string_selection(target, selection, opts)
end

---Encrypt the plain YAML value under the cursor.
---@param opts? table
function M.encrypt_string_under_cursor(opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_plain_yaml_value_under_cursor(target)

  if not selection then
    vim.notify("No plain YAML key/value found under cursor", vim.log.levels.WARN)
    return
  end

  encrypt_string_selection(target, selection, opts)
end

---@param path string
---@param data string
---@return boolean
---@return string|nil
local function atomic_write_file(path, data)
  local dir = vim.fn.fnamemodify(path, ":h")
  local tail = vim.fn.fnamemodify(path, ":t")
  local bytes = uv.random(4)
  local nonce = bytes:byte(1) * 16777216 + bytes:byte(2) * 65536 + bytes:byte(3) * 256 + bytes:byte(4)
  local tmp = string.format("%s/.%s.ansible-vault.nvim.%d.%d", dir, tail, uv.getpid(), nonce)

  local mode = DEFAULT_FILE_MODE
  local stat = uv.fs_stat(path)
  if stat and stat.mode then
    mode = stat.mode % 512
  end

  local fd, open_err = uv.fs_open(tmp, "wx", mode)
  if not fd then
    return false, open_err or "failed to create temporary output file"
  end

  local written, write_err = uv.fs_write(fd, data)
  if type(written) == "number" and written >= #data then
    -- Durability matters here: the rename replaces the only copy of the
    -- ciphertext, so the new contents have to be on disk before it happens.
    uv.fs_fsync(fd)
  end
  uv.fs_close(fd)

  if type(written) ~= "number" or written < #data then
    os.remove(tmp)
    return false, write_err or "failed to write encrypted output"
  end

  local ok, rename_err = uv.fs_rename(tmp, path)
  if not ok then
    os.remove(tmp)
    return false, rename_err or "failed to replace original file"
  end

  local dir_fd = uv.fs_open(dir, "r", DEFAULT_FILE_MODE)
  if dir_fd then
    pcall(uv.fs_fsync, dir_fd)
    uv.fs_close(dir_fd)
  end

  return true, nil
end

--- Inline region tracking -------------------------------------------------
---
---After `:VaultDecryptString` the buffer holds one decrypted value inside an
---otherwise ordinary YAML file. An extmark follows that region through
---subsequent edits so `:w` can fold exactly it back into a `!vault` block.

---@param buf integer
---@param start_row integer 0-based
---@param end_row integer 0-based
---@param parsed table
local function track_inline_region(buf, start_row, end_row, parsed)
  local end_line = vim.api.nvim_buf_get_lines(buf, end_row, end_row + 1, false)[1] or ""
  local id = vim.api.nvim_buf_set_extmark(buf, NAMESPACE, start_row, 0, {
    end_row = end_row,
    end_col = #end_line,
    right_gravity = false,
    end_right_gravity = true,
  })

  local regions = vim.b[buf].ansible_vault_inline or {}
  table.insert(regions, {
    id = id,
    name = parsed.var_name,
    indent = parsed.indent or "",
    dash = parsed.dash or "",
    label = parsed.header and parsed.header.label or nil,
  })
  vim.b[buf].ansible_vault_inline = regions
end

---Recover the scalar the user currently sees in a tracked region.
---@param lines string[]
---@param region table
---@return string name
---@return string content
local function inline_region_value(lines, region)
  if #lines == 1 then
    local _, key, value = yaml.extract_key_value(lines[1])
    return key or region.name, value or lines[1]
  end

  -- A multi-line value was written back as `key: |` plus an indented body.
  local min_indent = math.huge
  for i = 2, #lines do
    if lines[i]:match("%S") then
      min_indent = math.min(min_indent, yaml.indent_width(lines[i]))
    end
  end

  local body = {}
  for i = 2, #lines do
    table.insert(body, min_indent < math.huge and lines[i]:sub(min_indent + 1) or lines[i])
  end

  local key_line = yaml.parse_key_line(lines[1])
  return key_line and key_line.key or region.name, table.concat(body, "\n")
end

---Re-encrypt every tracked inline region back into the buffer.
---@param buf integer
---@param opts? table
---@param callback fun(ok: boolean)
restore_inline_regions = function(buf, opts, callback)
  local regions = vim.b[buf].ansible_vault_inline or {}
  if #regions == 0 then
    callback(true)
    return
  end

  local resolved = {}
  for _, region in ipairs(regions) do
    local ok, mark = pcall(vim.api.nvim_buf_get_extmark_by_id, buf, NAMESPACE, region.id, { details = true })
    if ok and mark and mark[1] and mark[3] then
      table.insert(resolved, {
        region = region,
        start_row = mark[1],
        end_row = math.max(mark[1], mark[3].end_row or mark[1]),
      })
    end
  end

  -- Bottom-up, so an earlier replacement cannot shift a later one.
  table.sort(resolved, function(a, b)
    return a.start_row > b.start_row
  end)

  local context = buffer_context(buf)

  get_credentials(function(creds)
    if not creds then
      callback(false)
      return
    end

    local index = 0
    local function step()
      index = index + 1
      if index > #resolved then
        run_cleanup(creds.cleanup)
        callback(true)
        return
      end

      local entry = resolved[index]
      local region = entry.region
      local lines = vim.api.nvim_buf_get_lines(buf, entry.start_row, entry.end_row + 1, false)
      local name, content = inline_region_value(lines, region)

      local args = with_encrypt_vault_id(
        creds.args,
        opts,
        creds,
        vim.tbl_extend("force", context, { header_label = region.label or context.header_label })
      )
      table.insert(args, "--stdin-name")
      table.insert(args, name or "encrypted_string")

      run_vault("encrypt_string", content, args, function(success, output)
        if not success then
          run_cleanup(creds.cleanup)
          vim.notify("Failed to re-encrypt " .. (name or "value") .. ": " .. output, vim.log.levels.ERROR)
          callback(false)
          return
        end

        local out_lines = output_to_lines(output)
        while #out_lines > 0 and out_lines[#out_lines] == "" do
          table.remove(out_lines, #out_lines)
        end

        local indent = region.indent or ""
        local dash = region.dash or ""
        local continuation = indent .. string.rep(" ", #dash)
        for i, line in ipairs(out_lines) do
          out_lines[i] = (i == 1 and indent .. dash or continuation) .. line
        end

        local ok = pcall(vim.api.nvim_buf_set_lines, buf, entry.start_row, entry.end_row + 1, false, out_lines)
        if not ok then
          run_cleanup(creds.cleanup)
          vim.notify("Failed to update buffer while re-encrypting", vim.log.levels.ERROR)
          callback(false)
          return
        end

        step()
      end, opts, creds)
    end

    step()
  end, opts, context)
end

---Write a buffer that is currently holding decrypted content.
---
---Reached only through the BufWriteCmd installed by `enter_plaintext_mode`, so
---this is the single place plaintext can turn into bytes on disk -- and it never
---writes those bytes, only the ciphertext `ansible-vault` returns.
---@param buf integer
---@param target_path string
---@param opts? table
write_plaintext_buffer = function(buf, target_path, opts)
  if not is_valid_buf(buf) then
    return
  end

  if vim.b[buf].ansible_vault_write_pending then
    vim.notify("Vault write already in progress", vim.log.levels.WARN)
    return
  end

  local path = target_path
  if not is_nonempty_string(path) then
    path = vim.api.nvim_buf_get_name(buf)
  end
  if not is_nonempty_string(path) then
    vim.notify("Cannot write a vault buffer with no file name", vim.log.levels.ERROR)
    return
  end

  local mode = vim.b[buf].ansible_vault_plaintext
  vim.b[buf].ansible_vault_write_pending = true

  local done = false

  local function finish(ok)
    done = true
    if is_valid_buf(buf) then
      vim.b[buf].ansible_vault_write_pending = nil
      if ok then
        vim.bo[buf].modified = false
      end
    end
  end

  -- `:w` has to have finished by the time it returns, or `:wq` would try to quit
  -- while the encryption is still in flight. The event loop keeps running, so
  -- this waits without freezing the job that does the work.
  local function await()
    local budget = get_timeout_ms(opts) or 30000
    if not vim.wait(budget + 1000, function()
      return done
    end, 20) then
      vim.notify("Timed out waiting for the vault write to finish", vim.log.levels.ERROR)
    end
  end

  if mode == "inline" then
    -- Fold the decrypted values back into the buffer, then write it as the plain
    -- YAML it now is. Buffer and file stay in agreement.
    restore_inline_regions(buf, opts, function(ok)
      if not ok then
        finish(false)
        return
      end

      -- Written as ordinary YAML, so the buffer's own line endings and trailing
      -- newline have to be reproduced rather than assumed.
      local eol = vim.bo[buf].fileformat == "dos" and "\r\n" or "\n"
      local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
      local body = table.concat(lines, eol) .. (vim.bo[buf].endofline and eol or "")

      local write_ok, write_err = atomic_write_file(path, body)
      if not write_ok then
        vim.notify("Failed to write file: " .. tostring(write_err), vim.log.levels.ERROR)
        finish(false)
        return
      end

      leave_plaintext_mode(buf)
      notify("Vault values restored and saved: " .. path, vim.log.levels.INFO, opts)
      emit_event("save", "inline", { buf = buf, file = path })
      finish(true)
    end)
    await()
    return
  end

  local context = buffer_context(buf)
  local content = buffer_content(buf)

  get_credentials(function(creds)
    if not creds then
      finish(false)
      return
    end

    local args = with_encrypt_vault_id(creds.args, opts, creds, context)

    run_vault("encrypt", content, args, function(success, output)
      run_cleanup(creds.cleanup)

      if not success then
        vim.notify("Encryption failed, nothing was written: " .. output, vim.log.levels.ERROR)
        finish(false)
        return
      end

      local write_ok, write_err = atomic_write_file(path, output)
      if not write_ok then
        vim.notify("Failed to write encrypted file: " .. tostring(write_err), vim.log.levels.ERROR)
        finish(false)
        return
      end

      notify("Encrypted and saved: " .. path, vim.log.levels.INFO, opts)
      emit_event("save", "file", { buf = buf, file = path })
      finish(true)
    end, opts, creds)
  end, opts, context)

  await()
end

---@param path string
---@return table|nil
local function file_signature(path)
  local stat = uv.fs_stat(path)
  if not stat then
    return nil
  end

  return {
    size = stat.size,
    mtime_sec = stat.mtime and stat.mtime.sec or 0,
    mtime_nsec = stat.mtime and stat.mtime.nsec or 0,
    ctime_sec = stat.ctime and stat.ctime.sec or 0,
    ctime_nsec = stat.ctime and stat.ctime.nsec or 0,
  }
end

---@param left table|nil
---@param right table|nil
---@return boolean
local function same_file_signature(left, right)
  if not left or not right then
    return left == right
  end

  return left.size == right.size
    and left.mtime_sec == right.mtime_sec
    and left.mtime_nsec == right.mtime_nsec
    and left.ctime_sec == right.ctime_sec
    and left.ctime_nsec == right.ctime_nsec
end

---@param edit_buf integer
local function cleanup_edit_buffer(edit_buf)
  if not is_valid_buf(edit_buf) then
    return
  end

  local cleanup = vim.b[edit_buf].vault_cleanup
  if cleanup then
    cleanup()
    vim.b[edit_buf].vault_cleanup = nil
  end
end

---@param edit_buf integer
---@param original_buf integer
---@param original_file string
---@param preferred_win integer
local function close_edit_buffer(edit_buf, original_buf, original_file, preferred_win)
  if is_valid_buf(original_buf) then
    vim.b[original_buf].ansible_vault_skip_auto_edit_once = true
    pcall(vim.api.nvim_buf_call, original_buf, function()
      vim.cmd("silent! edit!")
    end)
  end

  if is_valid_buf(edit_buf) then
    vim.bo[edit_buf].modified = false
  end

  local win = vim.api.nvim_win_is_valid(preferred_win) and preferred_win or vim.api.nvim_get_current_win()
  if is_valid_buf(original_buf) and vim.api.nvim_win_is_valid(win) then
    vim.api.nvim_win_set_buf(win, original_buf)
  elseif vim.api.nvim_win_is_valid(win) then
    vim.api.nvim_set_current_win(win)
    vim.cmd("edit " .. vim.fn.fnameescape(original_file))
  end

  if is_valid_buf(edit_buf) then
    vim.api.nvim_buf_delete(edit_buf, { force = true })
  end
end

---Edit encrypted buffer using a scratch buffer.
---@param buf? integer
---@param opts? table
function M.edit(buf, opts)
  local original_buf = normalize_buf(buf)
  if not is_valid_buf(original_buf) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  if not M.is_buffer_encrypted(original_buf) then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  if vim.bo[original_buf].modified then
    vim.notify("Write or discard changes before VaultEdit", vim.log.levels.ERROR)
    return
  end

  local original_file = vim.api.nvim_buf_get_name(original_buf)
  if original_file == "" then
    vim.notify("VaultEdit requires a file-backed buffer", vim.log.levels.ERROR)
    return
  end

  local original_win = vim.api.nvim_get_current_win()
  local filetype = vim.bo[original_buf].filetype
  local original_tick = changedtick(original_buf)
  local original_signature = file_signature(original_file)

  debug_log("VaultEdit: original_buf=%d", original_buf)

  local context = buffer_context(original_buf)

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not is_valid_buf(original_buf) then
      run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    run_vault("decrypt", buffer_content(original_buf), creds.args, function(success, output)
      if not success then
        run_cleanup(creds.cleanup)
        clear_password_cache()
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if not is_valid_buf(original_buf) then
        run_cleanup(creds.cleanup)
        vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if changedtick(original_buf) ~= original_tick then
        run_cleanup(creds.cleanup)
        vim.notify("Original buffer changed before VaultEdit opened; edit was cancelled", vim.log.levels.ERROR)
        return
      end

      -- Harden before the decrypted lines land, not after.
      local edit_buf = secure.create_buffer(true, false)
      secure.protect(edit_buf)
      local decrypted_lines = output_to_lines(output)
      secure.with_cleared_undo(edit_buf, function()
        vim.api.nvim_buf_set_lines(edit_buf, 0, -1, false, decrypted_lines)
      end)

      vim.bo[edit_buf].buftype = "acwrite"
      vim.bo[edit_buf].bufhidden = "wipe"
      vim.bo[edit_buf].filetype = filetype
      vim.bo[edit_buf].modified = false
      local set_name_ok, set_name_err = pcall(vim.api.nvim_buf_set_name, edit_buf, "ansible-vault://" .. original_file)
      if not set_name_ok then
        run_cleanup(creds.cleanup)
        pcall(vim.api.nvim_buf_delete, edit_buf, { force = true })
        vim.notify("VaultEdit: buffer name conflict - " .. (set_name_err or "E95"), vim.log.levels.ERROR)
        return
      end

      vim.b[edit_buf].vault_original_buf = original_buf
      vim.b[edit_buf].vault_original_file = original_file
      vim.b[edit_buf].vault_original_signature = original_signature
      vim.b[edit_buf].vault_creds = creds
      vim.b[edit_buf].vault_context = context
      vim.b[edit_buf].vault_cleanup = creds.cleanup
      vim.b[edit_buf].vault_write_pending = false

      local placed = false
      if vim.api.nvim_win_is_valid(original_win) and vim.api.nvim_win_get_buf(original_win) == original_buf then
        placed = pcall(vim.api.nvim_win_set_buf, original_win, edit_buf)
      end

      if not placed then
        local split_ok = pcall(vim.cmd, "botright split")
        if split_ok then
          placed = pcall(vim.api.nvim_win_set_buf, 0, edit_buf)
        end
      end

      if not placed then
        cleanup_edit_buffer(edit_buf)
        pcall(vim.api.nvim_buf_delete, edit_buf, { force = true })
        vim.notify("Failed to open VaultEdit scratch buffer", vim.log.levels.ERROR)
        return
      end

      vim.api.nvim_create_autocmd("BufWriteCmd", {
        buffer = edit_buf,
        callback = function(event)
          local cur_buf = event.buf
          if vim.b[cur_buf].vault_write_pending then
            vim.notify("VaultEdit save already in progress", vim.log.levels.WARN)
            return
          end

          vim.b[cur_buf].vault_write_pending = true
          local edit_content = table.concat(vim.api.nvim_buf_get_lines(cur_buf, 0, -1, false), "\n")
          local orig_file = vim.b[cur_buf].vault_original_file
          local orig_buf = vim.b[cur_buf].vault_original_buf
          local orig_signature = vim.b[cur_buf].vault_original_signature
          local edit_creds = vim.b[cur_buf].vault_creds
          local encrypt_args = with_encrypt_vault_id(edit_creds.args, opts, edit_creds, vim.b[cur_buf].vault_context)

          debug_log("VaultEdit: encrypting buffer %d", cur_buf)

          -- 'modified' stays set until the write actually lands. Clearing it up
          -- front would let `:q` wipe the buffer, and its plaintext, while the
          -- encryption is still in flight.
          run_vault("encrypt", edit_content, encrypt_args, function(enc_success, enc_output)
            if not enc_success then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Encryption failed: " .. enc_output, vim.log.levels.ERROR)
              return
            end

            if not same_file_signature(orig_signature, file_signature(orig_file)) then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Original file changed on disk; encrypted output was not written", vim.log.levels.ERROR)
              return
            end

            local write_ok, write_err = atomic_write_file(orig_file, enc_output)
            if not write_ok then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Failed to write encrypted file: " .. write_err, vim.log.levels.ERROR)
              return
            end

            if is_valid_buf(cur_buf) then
              vim.bo[cur_buf].modified = false
            end

            notify("Encrypted and saved: " .. orig_file, vim.log.levels.INFO, opts)
            emit_event("save", "file", { buf = orig_buf, file = orig_file })
            if is_valid_buf(cur_buf) then
              cleanup_edit_buffer(cur_buf)
              close_edit_buffer(cur_buf, orig_buf, orig_file, original_win)
            end
          end, opts, edit_creds)
        end,
      })

      vim.api.nvim_create_autocmd({ "BufDelete", "BufWipeout" }, {
        buffer = edit_buf,
        callback = function(event)
          cleanup_edit_buffer(event.buf)
          debug_log("VaultEdit: buffer closed")
        end,
      })

      notify("Editing decrypted content. :w encrypts and saves.", vim.log.levels.INFO, opts)
      emit_event("edit", "file", { buf = edit_buf, original_buf = original_buf, file = original_file })
    end, opts, creds)
  end, opts, context)
end

---Rekey the current encrypted file.
---@param opts? { args?: string[], overrides?: table, rekey_args?: string[] }
function M.rekey(opts)
  local target = vim.api.nvim_get_current_buf()
  if not is_valid_buf(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  if not M.is_buffer_encrypted(target) then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  if vim.bo[target].modified then
    vim.notify("Write or discard changes before VaultRekey", vim.log.levels.ERROR)
    return
  end

  local file_path = vim.api.nvim_buf_get_name(target)
  if file_path == "" then
    vim.notify("VaultRekey requires a file-backed buffer", vim.log.levels.ERROR)
    return
  end

  local context = buffer_context(target)

  get_credentials(function(creds)
    if not creds then
      return
    end

    local rekey_args = with_encrypt_vault_id(creds.args, opts, creds, context)
    vim.list_extend(rekey_args, with_rekey_target_args(opts and (opts.rekey_args or opts.args) or {}, opts))

    if not has_rekey_target(rekey_args) then
      run_cleanup(creds.cleanup)
      vim.notify(
        "VaultRekey requires rekey_password_file, rekey_vault_id, or --new-vault-* command args",
        vim.log.levels.ERROR
      )
      return
    end

    if not start_buffer_operation(target, "rekey") then
      run_cleanup(creds.cleanup)
      return
    end

    run_vault_file("rekey", file_path, rekey_args, function(success, output)
      run_cleanup(creds.cleanup)
      finish_buffer_operation(target, "rekey")

      if not success then
        vim.notify("Rekey failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if is_valid_buf(target) then
        pcall(vim.api.nvim_buf_call, target, function()
          vim.cmd("silent! edit!")
        end)
        remember_header(target)
      end

      notify("Vault file rekeyed successfully", vim.log.levels.INFO, opts)
      emit_event("rekey", "file", { buf = target, file = file_path })
    end, opts, creds)
  end, opts, context)
end

---Parse vault content from YAML format, removing indentation.
---@param content string
---@return table|nil
parse_vault_from_yaml = function(content)
  debug_log("parsing inline vault block (%d bytes)", #content)
  return yaml.parse_block(content)
end

local needs_yaml_quoting = yaml.needs_quoting
local yaml_quote_value = yaml.quote_value

---@param output string
---@param parsed table
---@return string[]
local function format_decrypt_string_output(output, parsed)
  local lines = output_to_lines(output)
  while #lines > 0 and lines[#lines] == "" do
    table.remove(lines, #lines)
  end

  if not parsed.var_name then
    return lines
  end

  local indent = parsed.indent or ""
  local dash = parsed.dash or ""
  local prefix = indent .. dash
  if #lines == 1 then
    return { prefix .. parsed.var_name .. ": " .. yaml_quote_value(lines[1]) }
  end

  local continuation = indent .. string.rep(" ", #dash) .. "  "
  local result = { prefix .. parsed.var_name .. ": |" }
  for _, line in ipairs(lines) do
    table.insert(result, continuation .. line)
  end
  return result
end

---@param selection AnsibleVaultSelection|nil
---@return table|nil parsed
local function parse_vault_selection(selection)
  if not selection or #selection.lines == 0 then
    vim.notify("No text selected", vim.log.levels.WARN)
    return nil
  end

  local parsed = parse_vault_from_yaml(table.concat(selection.lines, "\n"))

  if not parsed then
    vim.notify("Selected text does not appear to be vault encrypted", vim.log.levels.WARN)
    return nil
  end

  return parsed
end

---@param target integer
---@param selection AnsibleVaultSelection|nil
---@param mode "view"|"replace"
---@param opts? table
local function decrypt_string_selection(target, selection, mode, opts)
  local parsed = parse_vault_selection(selection)
  if not parsed then
    return
  end

  local planned_tick = changedtick(target)
  local filetype = vim.bo[target].filetype
  local context = buffer_context(target)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if mode == "replace" and not start_buffer_operation(target, "decrypt_string") then
      run_cleanup(creds.cleanup)
      return
    end

    run_vault("decrypt", parsed.vault_content, creds.args, function(success, output)
      run_cleanup(creds.cleanup)
      if mode == "replace" then
        finish_buffer_operation(target, "decrypt_string")
      end

      if not success then
        clear_password_cache()
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if mode == "view" then
        local title = parsed.var_name and string.format(" %s (read-only) ", parsed.var_name)
          or " Vault String (read-only) "
        open_output_window(output:gsub("\n$", ""), title, filetype)
        return
      end

      if not is_valid_buf(target) then
        vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if changedtick(target) ~= planned_tick then
        vim.notify("Vault operation finished, but the buffer changed; result was not applied", vim.log.levels.ERROR)
        return
      end

      local replacement = format_decrypt_string_output(output, parsed)

      -- Harden before the plaintext is spliced in, so it never reaches the swap
      -- file this buffer would otherwise keep.
      secure.protect(target)

      local ok, err = secure.with_cleared_undo(target, function()
        vim.api.nvim_buf_set_text(
          target,
          selection.start_row,
          selection.start_col,
          selection.end_row,
          selection.end_col,
          replacement
        )
      end)

      if ok then
        track_inline_region(target, selection.start_row, selection.start_row + #replacement - 1, parsed)
        enter_plaintext_mode(target, "inline", opts)
        notify("String decrypted successfully", vim.log.levels.INFO, opts)
        emit_event("decrypt", "inline", { buf = target, name = parsed.var_name })
      else
        vim.notify("Failed to update selection: " .. tostring(err), vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---View selected encrypted string in floating window.
---@param range_opts? table
---@param opts? table
function M.view_string(range_opts, opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_selection(target, range_opts)
  decrypt_string_selection(target, selection, "view", opts)
end

---Decrypt selected encrypted string in place.
---@param range_opts? table
---@param opts? table
function M.decrypt_string(range_opts, opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_selection(target, range_opts)
  decrypt_string_selection(target, selection, "replace", opts)
end

---View encrypted string under cursor in a floating window.
---@param opts? table
function M.view_string_under_cursor(opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = find_vault_block_under_cursor(target)
  decrypt_string_selection(target, selection, "view", opts)
end

---Decrypt encrypted string under cursor in place.
---@param opts? table
function M.decrypt_string_under_cursor(opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = find_vault_block_under_cursor(target)
  decrypt_string_selection(target, selection, "replace", opts)
end

---Create a new Ansible Vault file.
---
---Opens an empty, hardened buffer for the given path. The file is only created
---on `:w`, and only ever with encrypted content.
---@param opts? table
function M.create(opts)
  local path = opts and opts.positionals and opts.positionals[1]
  if not is_nonempty_string(path) then
    vim.notify("VaultCreate requires a file path", vim.log.levels.ERROR)
    return
  end

  path = vim.fn.fnamemodify(expand_path(path), ":p")

  if uv.fs_stat(path) and not (opts and opts.bang) then
    vim.notify("File already exists (use :VaultCreate! to overwrite): " .. path, vim.log.levels.ERROR)
    return
  end

  local dir = vim.fn.fnamemodify(path, ":h")
  local dir_stat = uv.fs_stat(dir)
  if not dir_stat or dir_stat.type ~= "directory" then
    vim.notify("Directory does not exist: " .. dir, vim.log.levels.ERROR)
    return
  end

  local ok, err = pcall(vim.cmd, "edit " .. vim.fn.fnameescape(path))
  if not ok then
    vim.notify("Failed to open " .. path .. ": " .. tostring(err), vim.log.levels.ERROR)
    return
  end

  local buf = vim.api.nvim_get_current_buf()
  secure.protect(buf)
  secure.with_cleared_undo(buf, function()
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "" })
  end)
  vim.bo[buf].modified = false

  enter_plaintext_mode(buf, "file", opts)
  emit_event("create", "file", { buf = buf, file = path })
end

---Clear the in-memory interactive password cache.
function M.clear_password_cache()
  clear_password_cache()
  notify("Ansible Vault password cache cleared", vim.log.levels.INFO)
end

---Drop every secret this process is still holding. Runs on exit.
function M.cleanup()
  clear_password_cache()
  credentials.cleanup_all()
end

--- Commands ---------------------------------------------------------------
---
---One table, one registration pass. The commands used to be declared both here
---and in `plugin/ansible-vault.lua`, each with `force = true`, so whichever ran
---last silently won.

---@param arg_lead string
---@return string[]
local function complete_create_args(arg_lead)
  local candidates = complete_operation_args(arg_lead)
  if not arg_lead:match("^%-") then
    vim.list_extend(candidates, vim.fn.getcompletion(arg_lead, "file"))
  end
  return vim.tbl_filter(function(candidate)
    return vim.startswith(candidate, arg_lead)
  end, candidates)
end

local COMPLETERS = {
  operation = function(arg_lead)
    return complete_operation_args(arg_lead)
  end,
  rekey = function(arg_lead)
    return complete_operation_args(arg_lead, true)
  end,
  labels = function(arg_lead)
    return complete_operation_args(arg_lead, false, true)
  end,
  create = complete_create_args,
}

---@type table[]
local COMMANDS = {
  {
    name = "VaultEncrypt",
    desc = "Encrypt current buffer with ansible-vault",
    complete = "operation",
    run = function(_, parsed)
      M.encrypt(nil, parsed)
    end,
  },
  {
    name = "VaultDecrypt",
    desc = "Decrypt current buffer with ansible-vault",
    complete = "operation",
    run = function(_, parsed)
      M.decrypt(nil, parsed)
    end,
  },
  {
    name = "VaultView",
    desc = "View encrypted buffer in floating window",
    complete = "operation",
    run = function(_, parsed)
      M.view(nil, parsed)
    end,
  },
  {
    name = "VaultEdit",
    desc = "Edit encrypted buffer in a secure scratch buffer",
    complete = "operation",
    run = function(_, parsed)
      M.edit(nil, parsed)
    end,
  },
  {
    name = "VaultCreate",
    desc = "Create a new Ansible Vault file",
    complete = "create",
    bang = true,
    run = function(cmd_opts, parsed)
      parsed.bang = cmd_opts.bang
      M.create(parsed)
    end,
  },
  {
    name = "VaultClearPasswordCache",
    desc = "Clear cached Ansible Vault password",
    nargs = 0,
    run = function()
      M.clear_password_cache()
    end,
  },
  {
    name = "VaultRekey",
    desc = "Rekey encrypted file with ansible-vault",
    complete = "rekey",
    run = function(_, parsed)
      M.rekey(parsed)
    end,
  },
  {
    name = "VaultEncryptString",
    desc = "Encrypt selected string",
    complete = "labels",
    range = true,
    parse = { label_shortcut = true },
    run = function(cmd_opts, parsed)
      M.encrypt_string(cmd_opts, parsed)
    end,
  },
  {
    name = "VaultDecryptString",
    desc = "Decrypt selected string",
    complete = "operation",
    range = true,
    run = function(cmd_opts, parsed)
      M.decrypt_string(cmd_opts, parsed)
    end,
  },
  {
    name = "VaultViewString",
    desc = "View selected encrypted string",
    complete = "operation",
    range = true,
    run = function(cmd_opts, parsed)
      M.view_string(cmd_opts, parsed)
    end,
  },
  {
    name = "VaultEncryptStringUnderCursor",
    desc = "Encrypt YAML value under cursor",
    complete = "labels",
    parse = { label_shortcut = true },
    run = function(_, parsed)
      M.encrypt_string_under_cursor(parsed)
    end,
  },
  {
    name = "VaultViewStringUnderCursor",
    desc = "View vault string under cursor",
    complete = "operation",
    run = function(_, parsed)
      M.view_string_under_cursor(parsed)
    end,
  },
  {
    name = "VaultDecryptStringUnderCursor",
    desc = "Decrypt vault string under cursor",
    complete = "operation",
    run = function(_, parsed)
      M.decrypt_string_under_cursor(parsed)
    end,
  },
}

local version_warned = false

---Apply the plugin's defaults when the user never called `setup()`.
local function ensure_configured()
  if not version_warned and vim.fn.has("nvim-" .. M.MIN_NVIM_VERSION) == 0 then
    version_warned = true
    vim.notify(
      string.format("ansible-vault.nvim supports Neovim %s and newer; older versions are untested", M.MIN_NVIM_VERSION),
      vim.log.levels.WARN
    )
  end

  if not M._configured then
    M.setup(vim.g.ansible_vault_config or {})
  end
end

---Register every user command. Idempotent.
function M.register_commands()
  for _, command in ipairs(COMMANDS) do
    vim.api.nvim_create_user_command(command.name, function(cmd_opts)
      ensure_configured()
      command.run(cmd_opts, parse_operation_options(parse_command_args(cmd_opts.args), command.parse))
    end, {
      nargs = command.nargs or "*",
      range = command.range or nil,
      bang = command.bang or nil,
      complete = command.complete and COMPLETERS[command.complete] or nil,
      desc = command.desc,
      force = true,
    })
  end
end

---Setup the plugin.
---@param opts? AnsibleVaultConfig
function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", vim.deepcopy(DEFAULT_CONFIG), opts or {})
  M._configured = true

  ansible_cfg.clear_cache()
  M.register_commands()

  local group = vim.api.nvim_create_augroup(AUGROUP, { clear = true })

  -- Secrets must not outlive the process, and a crash is the case that matters.
  -- This covers the orderly exit; anything the plugin writes is also named after
  -- this process so a crashed instance's leftovers are identifiable.
  vim.api.nvim_create_autocmd("VimLeavePre", {
    group = group,
    desc = "Drop cached Ansible Vault secrets",
    callback = function()
      M.cleanup()
    end,
  })

  -- Re-reading a file replaces whatever the buffer held, so any plaintext state
  -- tracked for it is stale.
  vim.api.nvim_create_autocmd("BufReadPre", {
    group = group,
    pattern = "*",
    callback = function(event)
      if vim.b[event.buf].ansible_vault_plaintext then
        leave_plaintext_mode(event.buf)
      end
    end,
  })

  if M.config.auto_detect or M.config.auto_edit then
    vim.api.nvim_create_autocmd("BufReadPost", {
      group = group,
      pattern = "*",
      callback = function(event)
        local encrypted = M.is_buffer_encrypted(event.buf)
        if M.config.auto_detect then
          remember_header(event.buf)
        end

        if vim.b[event.buf].ansible_vault_skip_auto_edit_once then
          vim.b[event.buf].ansible_vault_skip_auto_edit_once = nil
          return
        end

        if encrypted and M.config.auto_edit then
          vim.schedule(function()
            if is_valid_buf(event.buf) and M.is_buffer_encrypted(event.buf) then
              M.edit(event.buf)
            end
          end)
        end
      end,
    })
  end
end

M._private = {
  build_vault_argv = build_vault_argv,
  expand_vault_id = expand_vault_id,
  parse_vault_from_yaml = parse_vault_from_yaml,
  output_to_lines = output_to_lines,
  complete_operation_args = complete_operation_args,
  complete_create_args = complete_create_args,
  needs_yaml_quoting = needs_yaml_quoting,
  yaml_quote_value = yaml_quote_value,
  redact_argv = redact_argv,
  effective_config = effective_config,
}

return M
