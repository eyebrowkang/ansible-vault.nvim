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
---@field picker? "auto"|"telescope"|"builtin" Picker backend for VaultFiles (default: "auto")
---@field timeout_ms? number ansible-vault job timeout in milliseconds (default: 30000, set 0 to disable)
---@field notify_success? boolean Show success/info notifications (default: true)
---@field conda_env? string Conda environment name where ansible-vault is installed
---@field ansible_vault_path? string Custom path to ansible-vault executable
---@field debug? boolean Enable debug logging (default: false)

local M = {}

local uv = vim.uv or vim.loop
local VAULT_HEADER = "^%$ANSIBLE_VAULT;[%d%.]+;AES256"
local AUGROUP = "AnsibleVault"
local PASSWORD_FILE_MODE = 384 -- 0600
local parse_vault_from_yaml
local extract_vault_from_yaml
local has_rekey_target

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
  picker = "auto",
  timeout_ms = 30000,
  notify_success = true,
  conda_env = nil,
  ansible_vault_path = nil,
  debug = false,
}

---@type AnsibleVaultConfig
M.config = vim.deepcopy(DEFAULT_CONFIG)

local password_cache = {
  password = nil,
  expires_at = 0,
}

local last_operation = nil
local suppress_auto_edit_path = nil

---Debug log helper
---@param msg string
---@param ... any
local function debug_log(msg, ...)
  if M.config.debug then
    local formatted = string.format(msg, ...)
    vim.notify("[ansible-vault DEBUG] " .. formatted, vim.log.levels.DEBUG)
    print("[ansible-vault DEBUG] " .. formatted)
  end
end

---@param value any
---@return boolean
local function is_nonempty_string(value)
  return type(value) == "string" and value ~= ""
end

---@param opts? table
---@return table
local function effective_config(opts)
  local overrides = opts and (opts.overrides or opts) or {}
  return vim.tbl_deep_extend("force", M.config, overrides)
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

---@param operation string
---@param data? table
local function emit_event(operation, data)
  local payload = vim.tbl_deep_extend("force", { operation = operation }, data or {})
  last_operation = {
    operation = operation,
    time = os.time(),
    data = payload,
  }

  pcall(vim.api.nvim_exec_autocmds, "User", {
    pattern = "AnsibleVault" .. operation,
    data = payload,
  })
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

---@param job_id integer
---@param action string
---@param opts? table
---@return fun()
---@return fun(): boolean
local function start_job_timeout(job_id, action, opts)
  local timeout = get_timeout_ms(opts)
  if not timeout then
    return function() end, function()
      return false
    end
  end

  local timed_out = false
  local timer = uv.new_timer()
  if not timer then
    return function() end, function()
      return false
    end
  end

  timer:start(timeout, 0, function()
    timed_out = true
    vim.schedule(function()
      pcall(vim.fn.jobstop, job_id)
    end)
  end)

  local stop = function()
    if timer and not timer:is_closing() then
      timer:stop()
      timer:close()
    end
  end

  return stop, function()
    return timed_out
  end
end

---@param ttl any
---@return boolean
local function should_cache_password(ttl)
  return type(ttl) == "number" and ttl > 0
end

---@return integer
local function now_seconds()
  return os.time()
end

local function clear_password_cache()
  password_cache.password = nil
  password_cache.expires_at = 0
end

---@param path string
---@return string
local function expand_path(path)
  return vim.fn.expand(path)
end

---@param vault_id string
---@return string
local function expand_vault_id(vault_id)
  local label, source = vault_id:match("^([^@]+)@(.+)$")
  if not label or not source or source == "prompt" then
    return vault_id
  end

  return label .. "@" .. expand_path(source)
end

---@param opts? table
---@return string[]
local function get_vault_argv(opts)
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
  local argv = get_vault_argv(opts)
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

---@param data string[]
---@param chunk string[]|nil
local function collect_job_data(data, chunk)
  if not chunk then
    return
  end

  for _, item in ipairs(chunk) do
    if item ~= nil then
      table.insert(data, item)
    end
  end
end

---@param data string[]
---@return string
local function join_job_data(data)
  local lines = vim.deepcopy(data)
  return table.concat(lines, "\n")
end

---@param output string
---@return string[]
local function output_to_lines(output)
  if output == "" then
    return { "" }
  end
  return vim.split(output, "\n", { plain = true })
end

---@param contents string
---@return string|nil path
---@return string|nil err
local function write_secure_tempfile(contents)
  local path = vim.fn.tempname()
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

  return path, nil
end

---@param callback fun(args: string[]|nil, cleanup?: fun())
---@param opts? table
local function get_password_args(callback, opts)
  local config = effective_config(opts)

  if is_nonempty_string(config.password_file) then
    callback({ "--vault-password-file", expand_path(config.password_file) })
    return
  end

  local vault_ids = {}
  if type(config.vault_ids) == "table" and #config.vault_ids > 0 then
    for _, vault_id in ipairs(config.vault_ids) do
      if is_nonempty_string(vault_id) then
        table.insert(vault_ids, expand_vault_id(vault_id))
      end
    end
  elseif is_nonempty_string(config.vault_id) then
    table.insert(vault_ids, expand_vault_id(config.vault_id))
  end

  if #vault_ids > 0 then
    local args = {}
    for _, vault_id in ipairs(vault_ids) do
      table.insert(args, "--vault-id")
      table.insert(args, vault_id)
    end
    callback(args)
    return
  end

  if
    should_cache_password(config.password_cache_ttl)
    and password_cache.password
    and password_cache.expires_at > now_seconds()
  then
    local tmpfile, err = write_secure_tempfile(password_cache.password .. "\n")
    if not tmpfile then
      vim.notify("Failed to create temp password file: " .. err, vim.log.levels.ERROR)
      callback(nil)
      return
    end

    local cleaned = false
    callback({ "--vault-password-file", tmpfile }, function()
      if cleaned then
        return
      end
      cleaned = true
      os.remove(tmpfile)
    end)
    return
  end

  local ok, password = pcall(vim.fn.inputsecret, "Ansible Vault Password: ")
  vim.cmd("redraw")

  if not ok or not password or password == "" then
    vim.notify("Password is required", vim.log.levels.ERROR)
    callback(nil)
    return
  end

  if should_cache_password(config.password_cache_ttl) then
    password_cache.password = password
    password_cache.expires_at = now_seconds() + config.password_cache_ttl
  else
    clear_password_cache()
  end

  local tmpfile, err = write_secure_tempfile(password .. "\n")
  if not tmpfile then
    vim.notify("Failed to create temp password file: " .. err, vim.log.levels.ERROR)
    callback(nil)
    return
  end

  local cleaned = false
  callback({ "--vault-password-file", tmpfile }, function()
    if cleaned then
      return
    end
    cleaned = true
    os.remove(tmpfile)
  end)
end

---@param args string[]
---@param opts? table
---@return string[]
local function with_encrypt_vault_id(args, opts)
  local config = effective_config(opts)
  local result = vim.deepcopy(args or {})
  if is_nonempty_string(config.encrypt_vault_id) then
    table.insert(result, "--encrypt-vault-id")
    table.insert(result, config.encrypt_vault_id)
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

---Run ansible-vault command.
---@param action string The vault action (encrypt, decrypt, encrypt_string)
---@param input string Input content
---@param args string[] Additional arguments
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
local function run_vault(action, input, args, callback, opts)
  local argv = build_vault_argv(action, args or {}, "-", opts)
  local stdout_data = {}
  local stderr_data = {}
  local stop_timeout = function() end
  local did_timeout = function()
    return false
  end

  debug_log("running: %s", table.concat(argv, " "))

  local job_id = vim.fn.jobstart(argv, {
    stdin = "pipe",
    stdout_buffered = true,
    stderr_buffered = true,
    on_stdout = function(_, data)
      collect_job_data(stdout_data, data)
    end,
    on_stderr = function(_, data)
      collect_job_data(stderr_data, data)
    end,
    on_exit = function(_, exit_code)
      vim.schedule(function()
        stop_timeout()
        local stdout = join_job_data(stdout_data)
        local stderr = join_job_data(stderr_data)

        if exit_code == 0 then
          callback(true, stdout)
          return
        end

        if did_timeout() then
          callback(false, string.format("ansible-vault %s timed out after %dms", action, get_timeout_ms(opts) or 0))
          return
        end

        callback(false, stderr ~= "" and stderr or stdout)
      end)
    end,
  })

  if job_id <= 0 then
    callback(false, "Failed to start ansible-vault")
    return
  end

  stop_timeout, did_timeout = start_job_timeout(job_id, action, opts)
  vim.fn.chansend(job_id, input)
  vim.fn.chanclose(job_id, "stdin")
end

---@param args string|nil
---@return string[]
local function parse_command_args(args)
  if not is_nonempty_string(args) then
    return {}
  end
  local result = {}
  local i = 1
  local len = #args
  while i <= len do
    local c = args:sub(i, i)
    if c == " " or c == "\t" then
      i = i + 1
    elseif c == "'" or c == '"' then
      local quote = c
      i = i + 1
      local start = i
      while i <= len and args:sub(i, i) ~= quote do
        i = i + 1
      end
      table.insert(result, args:sub(start, i - 1))
      if i <= len then
        i = i + 1
      end
    else
      local start = i
      while i <= len and args:sub(i, i) ~= " " and args:sub(i, i) ~= "\t" do
        i = i + 1
      end
      table.insert(result, args:sub(start, i - 1))
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
    git_ref = nil,
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
    elseif arg == "--git" then
      if next_arg and not next_arg:match("^%-") then
        result.git_ref = next_arg
        index = index + 2
      else
        result.git_ref = "HEAD"
        index = index + 1
      end
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

---@param arg_lead string
---@return string[]
local function complete_diff_args(arg_lead)
  local candidates = complete_operation_args(arg_lead)
  table.insert(candidates, "--git")

  if not arg_lead:match("^%-") then
    vim.list_extend(candidates, vim.fn.getcompletion(arg_lead, "file"))
  end

  return vim.tbl_filter(function(candidate)
    return vim.startswith(candidate, arg_lead)
  end, candidates)
end

---@param arg_lead string
---@return string[]
local function complete_files_args(arg_lead)
  local candidates = { "view", "edit", "rekey" }
  vim.list_extend(candidates, complete_operation_args(arg_lead, true))
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
local function run_vault_file(action, file_path, args, callback, opts)
  local argv = build_vault_argv(action, args or {}, file_path, opts)
  local stdout_data = {}
  local stderr_data = {}
  local stop_timeout = function() end
  local did_timeout = function()
    return false
  end

  debug_log("running: %s", table.concat(argv, " "))

  local job_id = vim.fn.jobstart(argv, {
    stdout_buffered = true,
    stderr_buffered = true,
    on_stdout = function(_, data)
      collect_job_data(stdout_data, data)
    end,
    on_stderr = function(_, data)
      collect_job_data(stderr_data, data)
    end,
    on_exit = function(_, exit_code)
      vim.schedule(function()
        stop_timeout()
        local stdout = join_job_data(stdout_data)
        local stderr = join_job_data(stderr_data)

        if exit_code == 0 then
          callback(true, stdout)
          return
        end

        if did_timeout() then
          callback(false, string.format("ansible-vault %s timed out after %dms", action, get_timeout_ms(opts) or 0))
          return
        end

        callback(false, stderr ~= "" and stderr or stdout)
      end)
    end,
  })

  if job_id <= 0 then
    callback(false, "Failed to start ansible-vault")
    return
  end

  stop_timeout, did_timeout = start_job_timeout(job_id, action, opts)
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
  local ok, err = pcall(vim.api.nvim_buf_set_lines, buf, 0, -1, false, lines)
  if not ok then
    vim.notify("Failed to update buffer: " .. err, vim.log.levels.ERROR)
    return false
  end

  vim.b[buf].ansible_vault_encrypted = M.is_encrypted(lines)
  notify(success_message, vim.log.levels.INFO, opts)
  return true
end

---@param output string
---@param title string
---@param filetype? string
local function open_output_window(output, title, filetype)
  local buf = vim.api.nvim_create_buf(false, true)
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

---Check if content is vault encrypted.
---@param content string|string[]
---@return boolean
function M.is_encrypted(content)
  local first_line
  if type(content) == "table" then
    first_line = content[1] or ""
  else
    first_line = content:match("^[^\n]*") or ""
  end
  return first_line:match(VAULT_HEADER) ~= nil
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

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if not start_buffer_operation(target, "encrypt") then
      run_cleanup(cleanup)
      return
    end

    local tick = changedtick(target)
    local content = buffer_content(target)

    run_vault("encrypt", content, with_encrypt_vault_id(args, opts), function(success, output)
      run_cleanup(cleanup)
      finish_buffer_operation(target, "encrypt")

      if success then
        if replace_buffer_lines(target, tick, output, "Buffer encrypted successfully", opts) then
          emit_event("Encrypt", { buf = target })
        end
      else
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts)
  end, opts)
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

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if not start_buffer_operation(target, "decrypt") then
      run_cleanup(cleanup)
      return
    end

    local tick = changedtick(target)
    local content = buffer_content(target)

    run_vault("decrypt", content, args, function(success, output)
      run_cleanup(cleanup)
      finish_buffer_operation(target, "decrypt")

      if success then
        if replace_buffer_lines(target, tick, output, "Buffer decrypted successfully", opts) then
          emit_event("Decrypt", { buf = target })
        end
      else
        clear_password_cache()
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts)
  end, opts)
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

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    run_vault("decrypt", buffer_content(target), args, function(success, output)
      run_cleanup(cleanup)

      if success then
        open_output_window(output, " Vault View (read-only) ", filetype)
        emit_event("View", { buf = target })
      else
        clear_password_cache()
        vim.notify("View failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts)
  end, opts)
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

---@param line string
---@return integer
local function line_indent(line)
  return #(line:match("^(%s*)") or "")
end

---@param line string
---@return string
local function strip_yaml_comment(line)
  local quote = nil
  local escaped = false

  for i = 1, #line do
    local char = line:sub(i, i)

    if quote then
      if quote == '"' and char == "\\" and not escaped then
        escaped = true
      else
        if char == quote and not escaped then
          quote = nil
        end
        escaped = false
      end
    elseif char == "'" or char == '"' then
      quote = char
    elseif char == "#" and (i == 1 or line:sub(i - 1, i - 1):match("%s")) then
      return line:sub(1, i - 1)
    end
  end

  return line
end

---@param value string
---@return string
local function unquote_yaml_value(value)
  local quote = value:match("^(['\"])")
  if not quote then
    return value
  end

  local escaped = false
  for i = 2, #value do
    local char = value:sub(i, i)
    if quote == '"' and char == "\\" and not escaped then
      escaped = true
    else
      if char == quote and not escaped then
        local result = value:sub(2, i - 1)
        if quote == '"' then
          result = result:gsub('\\"', '"'):gsub("\\\\", "\\")
        end
        return result
      end
      escaped = false
    end
  end

  return value:sub(2)
end

---@param line string
---@return string|nil indent
---@return string|nil key
---@return string|nil value
local function extract_yaml_key_value(line)
  local indent, key, rest = line:match("^(%s*)([%w_.%-]+):%s*(.*)$")
  if not key then
    return nil, nil, nil
  end
  if rest == "" or rest:match("^!vault") then
    return indent, key, nil
  end
  rest = strip_yaml_comment(rest)
  rest = rest:gsub("%s+$", "")
  if rest == "" then
    return indent, key, ""
  end
  return indent, key, unquote_yaml_value(rest)
end

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
  local line_count = vim.api.nvim_buf_line_count(buf)
  local start_row

  for row = cursor_row, 1, -1 do
    local line = vim.api.nvim_buf_get_lines(buf, row - 1, row, false)[1] or ""
    if line:match("!vault%s*|") then
      start_row = row
      break
    end

    if row ~= cursor_row and line:match("%S") and not line:match("^%s") then
      break
    end
  end

  if not start_row then
    local line = vim.api.nvim_buf_get_lines(buf, cursor_row - 1, cursor_row, false)[1] or ""
    if line:match("%$ANSIBLE_VAULT") then
      start_row = cursor_row
    else
      return nil
    end
  end

  local start_line = vim.api.nvim_buf_get_lines(buf, start_row - 1, start_row, false)[1] or ""
  local base_indent = line_indent(start_line)
  local end_row = start_row

  for row = start_row + 1, line_count do
    local line = vim.api.nvim_buf_get_lines(buf, row - 1, row, false)[1] or ""
    if line:match("%S") and line_indent(line) <= base_indent then
      break
    end
    end_row = row
  end

  if cursor_row > end_row then
    return nil
  end

  local selection = get_line_selection(buf, start_row, end_row)
  if not selection then
    return nil
  end

  local parsed = parse_vault_from_yaml(table.concat(selection.lines, "\n"))
  if not parsed or not parsed.vault_content or not parsed.vault_content:match("%$ANSIBLE_VAULT") then
    return nil
  end

  return selection
end

---@param text string
---@return string
local function escape_pattern(text)
  return text:gsub("([^%w])", "%%%1")
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

  local prefix = full_line:sub(1, selection.start_col)
  local indent, key = prefix:match("^(%s*)([%w_.%-]+):%s*$")
  if key then
    plan.name = key
    plan.mode = "value_only"
    plan.indent = indent
  end

  return plan
end

---@param output string
---@param plan table
---@return string[]
local function format_encrypt_string_output(output, plan)
  local lines = output_to_lines(output)

  if plan.mode == "value_only" then
    local key_pattern = "^%s*" .. escape_pattern(plan.name) .. ":%s*(.*)$"
    local first_value = lines[1] and lines[1]:match(key_pattern)
    if first_value then
      lines[1] = first_value
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

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    if not is_valid_buf(buf) then
      run_cleanup(cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if changedtick(buf) ~= planned_tick then
      run_cleanup(cleanup)
      vim.notify("Buffer changed before encryption started; result was not applied", vim.log.levels.ERROR)
      return
    end

    if not start_buffer_operation(buf, "encrypt_string") then
      run_cleanup(cleanup)
      return
    end

    local full_args = with_encrypt_vault_id(args, opts)
    table.insert(full_args, "--stdin-name")
    table.insert(full_args, plan.name)

    run_vault("encrypt_string", plan.content, full_args, function(success, output)
      run_cleanup(cleanup)
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
        emit_event("StringEncrypt", { buf = buf, name = plan.name })
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
    end, opts)
  end, opts)
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

---Toggle between encrypted and decrypted state.
---@param buf? integer
---@param opts? table
function M.toggle(buf, opts)
  local target = normalize_buf(buf)
  if M.is_buffer_encrypted(target) then
    M.decrypt(target, opts)
  else
    M.encrypt(target, opts)
  end
end

---@param path string
---@param data string
---@return boolean
---@return string|nil
local function atomic_write_file(path, data)
  local dir = vim.fn.fnamemodify(path, ":h")
  local tail = vim.fn.fnamemodify(path, ":t")
  local tmp = string.format("%s/.%s.ansible-vault.nvim.%d.%d", dir, tail, uv.getpid(), math.random(100000, 999999))

  local mode = PASSWORD_FILE_MODE
  local stat = uv.fs_stat(path)
  if stat and stat.mode then
    mode = stat.mode % 512
  end

  local fd, open_err = uv.fs_open(tmp, "wx", mode)
  if not fd then
    return false, open_err or "failed to create temporary output file"
  end

  local written, write_err = uv.fs_write(fd, data)
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

  return true, nil
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

  debug_log("VaultEdit: original_file=%s, original_buf=%d", original_file, original_buf)

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    if not is_valid_buf(original_buf) then
      run_cleanup(cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    run_vault("decrypt", buffer_content(original_buf), args, function(success, output)
      if not success then
        run_cleanup(cleanup)
        clear_password_cache()
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if not is_valid_buf(original_buf) then
        run_cleanup(cleanup)
        vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if changedtick(original_buf) ~= original_tick then
        run_cleanup(cleanup)
        vim.notify("Original buffer changed before VaultEdit opened; edit was cancelled", vim.log.levels.ERROR)
        return
      end

      local edit_buf = vim.api.nvim_create_buf(true, false)
      local decrypted_lines = output_to_lines(output)
      vim.api.nvim_buf_set_lines(edit_buf, 0, -1, false, decrypted_lines)

      vim.bo[edit_buf].buftype = "acwrite"
      vim.bo[edit_buf].bufhidden = "wipe"
      vim.bo[edit_buf].filetype = filetype
      vim.bo[edit_buf].swapfile = false
      vim.bo[edit_buf].undofile = false
      vim.bo[edit_buf].modified = false
      local set_name_ok, set_name_err = pcall(vim.api.nvim_buf_set_name, edit_buf, "ansible-vault://" .. original_file)
      if not set_name_ok then
        run_cleanup(cleanup)
        pcall(vim.api.nvim_buf_delete, edit_buf, { force = true })
        vim.notify("VaultEdit: buffer name conflict - " .. (set_name_err or "E95"), vim.log.levels.ERROR)
        return
      end

      vim.b[edit_buf].vault_original_buf = original_buf
      vim.b[edit_buf].vault_original_file = original_file
      vim.b[edit_buf].vault_original_signature = original_signature
      vim.b[edit_buf].vault_password_args = args
      vim.b[edit_buf].vault_cleanup = cleanup
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
          vim.bo[cur_buf].modified = false
          local edit_content = table.concat(vim.api.nvim_buf_get_lines(cur_buf, 0, -1, false), "\n")
          local orig_file = vim.b[cur_buf].vault_original_file
          local orig_buf = vim.b[cur_buf].vault_original_buf
          local orig_signature = vim.b[cur_buf].vault_original_signature
          local encrypt_args = with_encrypt_vault_id(vim.b[cur_buf].vault_password_args, opts)

          debug_log("VaultEdit: encrypting to %s", orig_file)

          run_vault("encrypt", edit_content, encrypt_args, function(enc_success, enc_output)
            if not enc_success then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
                vim.bo[cur_buf].modified = true
              end
              vim.notify("Encryption failed: " .. enc_output, vim.log.levels.ERROR)
              return
            end

            if not same_file_signature(orig_signature, file_signature(orig_file)) then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
                vim.bo[cur_buf].modified = true
              end
              vim.notify("Original file changed on disk; encrypted output was not written", vim.log.levels.ERROR)
              return
            end

            local write_ok, write_err = atomic_write_file(orig_file, enc_output)
            if not write_ok then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
                vim.bo[cur_buf].modified = true
              end
              vim.notify("Failed to write encrypted file: " .. write_err, vim.log.levels.ERROR)
              return
            end

            notify("Encrypted and saved: " .. orig_file, vim.log.levels.INFO, opts)
            emit_event("EditSave", { buf = orig_buf, file = orig_file })
            if is_valid_buf(cur_buf) then
              cleanup_edit_buffer(cur_buf)
              close_edit_buffer(cur_buf, orig_buf, orig_file, original_win)
            end
          end, opts)
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
      emit_event("EditOpen", { buf = edit_buf, original_buf = original_buf, file = original_file })
    end, opts)
  end, opts)
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

  get_password_args(function(password_args, cleanup)
    if not password_args then
      return
    end

    local rekey_args = with_encrypt_vault_id(password_args, opts)
    vim.list_extend(rekey_args, with_rekey_target_args(opts and (opts.rekey_args or opts.args) or {}, opts))

    if not has_rekey_target(rekey_args) then
      run_cleanup(cleanup)
      vim.notify(
        "VaultRekey requires rekey_password_file, rekey_vault_id, or --new-vault-* command args",
        vim.log.levels.ERROR
      )
      return
    end

    if not start_buffer_operation(target, "rekey") then
      run_cleanup(cleanup)
      return
    end

    run_vault_file("rekey", file_path, rekey_args, function(success, output)
      run_cleanup(cleanup)
      finish_buffer_operation(target, "rekey")

      if not success then
        vim.notify("Rekey failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if is_valid_buf(target) then
        pcall(vim.api.nvim_buf_call, target, function()
          vim.cmd("silent! edit!")
        end)
        vim.b[target].ansible_vault_encrypted = M.is_buffer_encrypted(target)
      end

      notify("Vault file rekeyed successfully", vim.log.levels.INFO, opts)
      emit_event("Rekey", { buf = target, file = file_path })
    end, opts)
  end, opts)
end

---Parse vault content from YAML format, removing indentation.
---@param content string
---@return table|nil
parse_vault_from_yaml = function(content)
  debug_log("VaultViewString: raw content:\n%s", content)

  local indent, var_name, after_vault = content:match("^(%s*)([%w_.%-]+):%s*!vault%s*|%s*\n(.+)")
  if not var_name then
    indent, after_vault = content:match("^(%s*)!vault%s*|%s*\n(.+)")
  end

  if after_vault then
    local vault_lines = vim.split(after_vault, "\n", { plain = true })
    local min_indent = math.huge
    for _, line in ipairs(vault_lines) do
      if line:match("%S") then
        local cur_indent = line_indent(line)
        min_indent = math.min(min_indent, cur_indent)
      end
    end

    if min_indent < math.huge and min_indent > 0 then
      for i, line in ipairs(vault_lines) do
        if #line >= min_indent then
          vault_lines[i] = line:sub(min_indent + 1)
        end
      end
    end

    local result = table.concat(vault_lines, "\n"):gsub("^%s+", ""):gsub("%s+$", "")
    return {
      vault_content = result,
      var_name = var_name,
      indent = indent or "",
    }
  end

  if content:match("%$ANSIBLE_VAULT") then
    local lines = vim.split(content, "\n", { plain = true })
    local min_indent = math.huge
    for _, line in ipairs(lines) do
      if line:match("%S") then
        local cur_indent = line_indent(line)
        min_indent = math.min(min_indent, cur_indent)
      end
    end

    if min_indent < math.huge and min_indent > 0 then
      for i, line in ipairs(lines) do
        if #line >= min_indent then
          lines[i] = line:sub(min_indent + 1)
        end
      end
    end

    local result = table.concat(lines, "\n"):gsub("^%s+", ""):gsub("%s+$", "")
    return {
      vault_content = result,
      var_name = nil,
      indent = "",
    }
  end

  return nil
end

---Extract vault content from YAML format, removing indentation.
---@param content string
---@return string|nil vault_content
---@return string|nil var_name
extract_vault_from_yaml = function(content)
  local parsed = parse_vault_from_yaml(content)
  if not parsed then
    return nil, nil
  end
  return parsed.vault_content, parsed.var_name
end

---@param output string
---@param parsed table
---@return string[]
local YAML_BOOLEAN_WORDS = {
  yes = true,
  no = true,
  ["true"] = true,
  ["false"] = true,
  null = true,
  on = true,
  off = true,
  y = true,
  n = true,
  Y = true,
  N = true,
  YES = true,
  NO = true,
  TRUE = true,
  FALSE = true,
  NULL = true,
  ON = true,
  OFF = true,
}

---@param value string
---@return boolean
local function needs_yaml_quoting(value)
  if value == "" then
    return true
  end
  local first_char = value:sub(1, 1)
  if first_char:match("[%[%{%]%}'\"&*!|>%%@`~]") then
    return true
  end
  if value:match("#") or value:match(": ") or value:match("%s$") or value:match("^%s") then
    return true
  end
  if YAML_BOOLEAN_WORDS[value] then
    return true
  end
  return false
end

---@param value string
---@return string
local function yaml_quote_value(value)
  if not needs_yaml_quoting(value) then
    return value
  end
  local escaped = value:gsub("\\", "\\\\"):gsub('"', '\\"')
  return '"' .. escaped .. '"'
end

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
  if #lines == 1 then
    return { indent .. parsed.var_name .. ": " .. yaml_quote_value(lines[1]) }
  end

  local result = { indent .. parsed.var_name .. ": |" }
  for _, line in ipairs(lines) do
    table.insert(result, indent .. "  " .. line)
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

  if not parsed or not parsed.vault_content or not parsed.vault_content:match("%$ANSIBLE_VAULT") then
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

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    if not is_valid_buf(target) then
      run_cleanup(cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if mode == "replace" and not start_buffer_operation(target, "decrypt_string") then
      run_cleanup(cleanup)
      return
    end

    run_vault("decrypt", parsed.vault_content, args, function(success, output)
      run_cleanup(cleanup)
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

      local ok, err = pcall(
        vim.api.nvim_buf_set_text,
        target,
        selection.start_row,
        selection.start_col,
        selection.end_row,
        selection.end_col,
        format_decrypt_string_output(output, parsed)
      )

      if ok then
        notify("String decrypted successfully", vim.log.levels.INFO, opts)
        emit_event("StringDecrypt", { buf = target, name = parsed.var_name })
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
    end, opts)
  end, opts)
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

---@param path string
---@return string|nil
---@return string|nil
local function read_text_file(path)
  local file, err = io.open(path, "r")
  if not file then
    return nil, err
  end

  local content = file:read("*a")
  file:close()
  return content, nil
end

---@param file_path string
---@param ref string
---@return string|nil
---@return string|nil
local function read_git_file(file_path, ref)
  local dir = vim.fn.fnamemodify(file_path, ":h")
  local rel = vim.fn.systemlist({ "git", "-C", dir, "ls-files", "--full-name", file_path })
  if vim.v.shell_error ~= 0 or not rel[1] or rel[1] == "" then
    return nil, "file is not tracked by git"
  end

  local lines = vim.fn.systemlist({ "git", "-C", dir, "show", ref .. ":" .. rel[1] })
  if vim.v.shell_error ~= 0 then
    return nil, table.concat(lines, "\n")
  end

  return table.concat(lines, "\n"), nil
end

---@param content string
---@param args string[]|nil
---@param opts? table
---@param callback fun(success: boolean, output: string): nil
local function decrypt_content_if_needed(content, args, opts, callback)
  if not M.is_encrypted(content) then
    callback(true, content)
    return
  end

  run_vault("decrypt", content, args or {}, callback, opts)
end

---@param name string
---@param content string
---@param filetype string
---@return integer
local function create_diff_buffer(name, content, filetype)
  local buf = vim.api.nvim_create_buf(true, false)
  pcall(vim.api.nvim_buf_set_name, buf, string.format("%s#%d", name, buf))
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, output_to_lines(content:gsub("\n$", "")))
  vim.bo[buf].buftype = "nofile"
  vim.bo[buf].bufhidden = "wipe"
  vim.bo[buf].swapfile = false
  vim.bo[buf].filetype = filetype
  vim.bo[buf].modifiable = false
  return buf
end

---@param left_name string
---@param left_content string
---@param right_name string
---@param right_content string
---@param filetype string
local function open_diff_tab(left_name, left_content, right_name, right_content, filetype)
  local left = create_diff_buffer(left_name, left_content, filetype)
  local right = create_diff_buffer(right_name, right_content, filetype)

  vim.cmd("tabnew")
  vim.api.nvim_win_set_buf(0, left)
  vim.cmd("diffthis")
  vim.cmd("vsplit")
  vim.api.nvim_win_set_buf(0, right)
  vim.cmd("diffthis")
end

---Diff the decrypted current buffer against a file or git revision.
---@param opts? table
function M.diff(opts)
  local target = vim.api.nvim_get_current_buf()
  if not is_valid_buf(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  local current_name = vim.api.nvim_buf_get_name(target)
  local target_name
  local target_content
  local err

  if opts and opts.git_ref then
    if current_name == "" then
      vim.notify("VaultDiff --git requires a file-backed buffer", vim.log.levels.ERROR)
      return
    end
    target_name = string.format("git:%s:%s", opts.git_ref, vim.fn.fnamemodify(current_name, ":t"))
    target_content, err = read_git_file(current_name, opts.git_ref)
  elseif opts and opts.positionals and opts.positionals[1] then
    local path = expand_path(opts.positionals[1])
    target_name = path
    target_content, err = read_text_file(path)
  else
    vim.notify("VaultDiff requires a file path or --git [ref]", vim.log.levels.ERROR)
    return
  end

  if not target_content then
    vim.notify("VaultDiff failed to read target: " .. (err or "unknown error"), vim.log.levels.ERROR)
    return
  end

  local current_content = buffer_content(target)
  local needs_password = M.is_encrypted(current_content) or M.is_encrypted(target_content)
  local filetype = vim.bo[target].filetype
  local current_title = current_name ~= "" and current_name or "[current buffer]"

  local function open_with_args(args, cleanup)
    decrypt_content_if_needed(current_content, args, opts, function(current_ok, current_plain)
      if not current_ok then
        run_cleanup(cleanup)
        clear_password_cache()
        vim.notify("VaultDiff failed to decrypt current buffer: " .. current_plain, vim.log.levels.ERROR)
        return
      end

      decrypt_content_if_needed(target_content, args, opts, function(target_ok, target_plain)
        run_cleanup(cleanup)
        if not target_ok then
          clear_password_cache()
          vim.notify("VaultDiff failed to decrypt target: " .. target_plain, vim.log.levels.ERROR)
          return
        end

        open_diff_tab(
          "ansible-vault-diff://current/" .. vim.fn.fnamemodify(current_title, ":t"),
          current_plain,
          "ansible-vault-diff://target/" .. vim.fn.fnamemodify(target_name, ":t"),
          target_plain,
          filetype
        )
        emit_event("Diff", { buf = target, target = target_name })
      end)
    end)
  end

  if needs_password then
    get_password_args(function(args, cleanup)
      if not args then
        return
      end
      open_with_args(args, cleanup)
    end, opts)
  else
    open_with_args({}, nil)
  end
end

---@return string[]
local function discover_vault_files()
  local files
  if vim.fn.executable("rg") == 1 then
    files = vim.fn.systemlist({ "rg", "--files" })
  else
    files = vim.fn.glob("**/*", false, true)
  end

  local result = {}
  for _, file in ipairs(files or {}) do
    if vim.fn.filereadable(file) == 1 then
      local first = vim.fn.readfile(file, "", 1)[1] or ""
      if M.is_encrypted({ first }) then
        table.insert(result, file)
      end
    end
  end

  table.sort(result)
  return result
end

---@param file string
---@param action string
---@param opts? table
local function open_vault_file_action(file, action, opts)
  suppress_auto_edit_path = vim.fn.fnamemodify(file, ":p")
  local ok, err = pcall(vim.cmd, "edit " .. vim.fn.fnameescape(file))
  suppress_auto_edit_path = nil
  if not ok then
    vim.notify("Failed to open vault file: " .. err, vim.log.levels.ERROR)
    return
  end

  local buf = vim.api.nvim_get_current_buf()

  if action == "edit" then
    M.edit(buf, opts)
  elseif action == "rekey" then
    M.rekey(opts)
  else
    M.view(buf, opts)
  end
end

---@param files string[]
---@param action string
---@param opts? table
---@return boolean
local function telescope_pick(files, action, opts)
  local config = effective_config(opts)
  if config.picker == "builtin" then
    return false
  end

  local ok_pickers, pickers = pcall(require, "telescope.pickers")
  local ok_finders, finders = pcall(require, "telescope.finders")
  local ok_conf, conf = pcall(require, "telescope.config")
  local ok_actions, actions = pcall(require, "telescope.actions")
  local ok_state, action_state = pcall(require, "telescope.actions.state")
  if not (ok_pickers and ok_finders and ok_conf and ok_actions and ok_state) then
    return false
  end

  local picker = pickers.new({}, {
    prompt_title = "Ansible Vault Files",
    finder = finders.new_table(files),
    sorter = conf.values.generic_sorter({}),
    attach_mappings = function(prompt_bufnr)
      actions.select_default:replace(function()
        local selection = action_state.get_selected_entry()
        actions.close(prompt_bufnr)
        if selection and selection.value then
          open_vault_file_action(selection.value, action, opts)
        end
      end)
      return true
    end,
  })
  picker:find()

  return true
end

---Pick a vault file and view/edit/rekey it.
---@param opts? table
function M.files(opts)
  local action = "view"
  if opts and opts.positionals and vim.tbl_contains({ "view", "edit", "rekey" }, opts.positionals[1]) then
    action = opts.positionals[1]
  end

  local files = discover_vault_files()
  if #files == 0 then
    vim.notify("No Ansible Vault files found", vim.log.levels.WARN)
    return
  end

  if telescope_pick(files, action, opts) then
    return
  end

  vim.ui.select(files, { prompt = "Ansible Vault files" }, function(choice)
    if choice then
      open_vault_file_action(choice, action, opts)
    end
  end)
end

---@param value boolean
---@return string
local function yes_no(value)
  return value and "yes" or "no"
end

---@param config table
---@return string
local function describe_password_source(config)
  if is_nonempty_string(config.password_file) then
    return "password_file"
  end

  if type(config.vault_ids) == "table" and #config.vault_ids > 0 then
    return string.format("vault_ids (%d)", #config.vault_ids)
  end

  if is_nonempty_string(config.vault_id) then
    return "vault_id"
  end

  return "interactive"
end

---@param config table
---@return string
local function describe_vault_labels(config)
  local labels = {}
  local add_label = function(vault_id)
    local label = type(vault_id) == "string" and vault_id:match("^([^@]+)@")
    if label then
      table.insert(labels, label)
    end
  end

  if type(config.vault_ids) == "table" then
    for _, vault_id in ipairs(config.vault_ids) do
      add_label(vault_id)
    end
  end
  add_label(config.vault_id)

  if #labels == 0 then
    return "none"
  end
  return table.concat(labels, ", ")
end

---@param config table
---@return string
local function describe_password_cache(config)
  if not should_cache_password(config.password_cache_ttl) then
    return "disabled"
  end

  if password_cache.password and password_cache.expires_at > now_seconds() then
    return string.format("active (%ds remaining)", password_cache.expires_at - now_seconds())
  end

  return "enabled, empty"
end

---Return human-readable plugin and buffer state lines.
---@param buf? integer
---@param opts? table
---@return string[]
function M.get_info(buf, opts)
  local target = normalize_buf(buf)
  local config = effective_config(opts)
  local buffer_name = is_valid_buf(target) and vim.api.nvim_buf_get_name(target) or ""
  local pending = is_valid_buf(target) and vim.b[target].ansible_vault_pending or nil
  local modified = is_valid_buf(target) and vim.bo[target].modified or false

  local timeout = get_timeout_ms(opts)
  local lines = {
    "Ansible Vault",
    "",
    "Buffer: " .. (buffer_name ~= "" and buffer_name or "[No Name]"),
    "Encrypted: " .. yes_no(is_valid_buf(target) and M.is_buffer_encrypted(target)),
    "Modified: " .. yes_no(modified),
    "Pending operation: " .. (pending or "none"),
    "",
    "Executable: " .. table.concat(get_vault_argv(opts), " "),
    "Credential source: " .. describe_password_source(config),
    "Vault labels: " .. describe_vault_labels(config),
    "Encrypt vault ID: " .. (is_nonempty_string(config.encrypt_vault_id) and config.encrypt_vault_id or "default"),
    "Rekey target: " .. (is_nonempty_string(config.rekey_password_file) and "password_file" or is_nonempty_string(
      config.rekey_vault_id
    ) and "vault_id" or "command args"),
    "",
    "Auto detect: " .. yes_no(config.auto_detect ~= false),
    "Auto edit: " .. yes_no(config.auto_edit == true),
    "Picker: " .. tostring(config.picker or "auto"),
    "Timeout: " .. (timeout and string.format("%dms", timeout) or "disabled"),
    "Success notifications: " .. yes_no(config.notify_success ~= false),
    "Password cache: " .. describe_password_cache(config),
  }

  if last_operation then
    table.insert(lines, "")
    table.insert(lines, "Last operation: " .. last_operation.operation)
    table.insert(lines, "Last operation time: " .. os.date("%Y-%m-%d %H:%M:%S", last_operation.time))
  end

  return lines
end

---Show plugin and current buffer state in a floating window.
---@param buf? integer
---@param opts? table
function M.info(buf, opts)
  open_output_window(table.concat(M.get_info(buf, opts), "\n"), " Ansible Vault Info ", "")
end

---Get status string for statusline.
---@param buf? integer
---@return string
function M.status(buf)
  if M.is_buffer_encrypted(buf) then
    return "[VAULT]"
  end
  return ""
end

---Clear the in-memory interactive password cache.
function M.clear_password_cache()
  clear_password_cache()
  notify("Ansible Vault password cache cleared", vim.log.levels.INFO)
end

---Setup the plugin.
---@param opts? AnsibleVaultConfig
function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", vim.deepcopy(DEFAULT_CONFIG), opts or {})
  M._configured = true

  vim.api.nvim_create_user_command("VaultEncrypt", function(command_opts)
    M.encrypt(nil, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "Encrypt current buffer with ansible-vault",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultDecrypt", function(command_opts)
    M.decrypt(nil, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "Decrypt current buffer with ansible-vault",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultView", function(command_opts)
    M.view(nil, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "View encrypted buffer in floating window",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultToggle", function(command_opts)
    M.toggle(nil, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "Toggle vault encryption state",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultEdit", function(command_opts)
    M.edit(nil, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "Edit encrypted buffer in a secure scratch buffer",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultClearPasswordCache", function()
    M.clear_password_cache()
  end, { desc = "Clear cached Ansible Vault password", force = true })

  vim.api.nvim_create_user_command("VaultDiff", function(command_opts)
    M.diff(parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_diff_args(arg_lead)
    end,
    desc = "Diff decrypted vault content",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultFiles", function(command_opts)
    M.files(parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_files_args(arg_lead)
    end,
    desc = "Pick an Ansible Vault file",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultInfo", function(command_opts)
    M.info(nil, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead, true)
    end,
    desc = "Show Ansible Vault buffer and configuration info",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultRekey", function(command_opts)
    M.rekey(parse_operation_options(parse_command_args(command_opts.args), { rekey = true }))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead, true)
    end,
    desc = "Rekey encrypted file with ansible-vault",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultEncryptString", function(command_opts)
    M.encrypt_string(
      command_opts,
      parse_operation_options(parse_command_args(command_opts.args), { label_shortcut = true })
    )
  end, {
    range = true,
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead, false, true)
    end,
    desc = "Encrypt selected string",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultDecryptString", function(command_opts)
    M.decrypt_string(command_opts, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    range = true,
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "Decrypt selected string",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultViewString", function(command_opts)
    M.view_string(command_opts, parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    range = true,
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "View selected encrypted string",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultEncryptStringUnderCursor", function(command_opts)
    M.encrypt_string_under_cursor(
      parse_operation_options(parse_command_args(command_opts.args), { label_shortcut = true })
    )
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead, false, true)
    end,
    desc = "Encrypt YAML value under cursor",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultViewStringUnderCursor", function(command_opts)
    M.view_string_under_cursor(parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "View vault string under cursor",
    force = true,
  })

  vim.api.nvim_create_user_command("VaultDecryptStringUnderCursor", function(command_opts)
    M.decrypt_string_under_cursor(parse_operation_options(parse_command_args(command_opts.args)))
  end, {
    nargs = "*",
    complete = function(arg_lead)
      return complete_operation_args(arg_lead)
    end,
    desc = "Decrypt vault string under cursor",
    force = true,
  })

  local group = vim.api.nvim_create_augroup(AUGROUP, { clear = true })
  if M.config.auto_detect or M.config.auto_edit then
    vim.api.nvim_create_autocmd("BufReadPost", {
      group = group,
      pattern = "*",
      callback = function(event)
        local encrypted = M.is_buffer_encrypted(event.buf)
        if M.config.auto_detect then
          vim.b[event.buf].ansible_vault_encrypted = encrypted
        end

        if vim.b[event.buf].ansible_vault_skip_auto_edit_once then
          vim.b[event.buf].ansible_vault_skip_auto_edit_once = nil
          return
        end

        if
          suppress_auto_edit_path
          and vim.fn.fnamemodify(vim.api.nvim_buf_get_name(event.buf), ":p") == suppress_auto_edit_path
        then
          suppress_auto_edit_path = nil
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

M._parse_command_options = function(args_str, opts)
  return parse_operation_options(parse_command_args(args_str), opts)
end

M._private = {
  build_vault_argv = build_vault_argv,
  expand_vault_id = expand_vault_id,
  extract_vault_from_yaml = extract_vault_from_yaml,
  get_vault_argv = get_vault_argv,
  parse_vault_from_yaml = parse_vault_from_yaml,
  output_to_lines = output_to_lines,
  complete_operation_args = complete_operation_args,
  complete_diff_args = complete_diff_args,
  complete_files_args = complete_files_args,
  yaml_quote_value = yaml_quote_value,
}

return M
