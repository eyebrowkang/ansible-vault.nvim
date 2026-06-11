---@class AnsibleVaultConfig
---@field password_file? string Path to ansible-vault password file
---@field vault_id? string Vault ID to use, for example "prod@~/.vault_pass"
---@field vault_ids? string[] Vault IDs to use, for example { "dev@~/.dev-pass", "prod@~/.prod-pass" }
---@field encrypt_vault_id? string Vault ID label to use for encryption
---@field rekey_password_file? string New vault password file for VaultRekey
---@field rekey_vault_id? string New vault ID for VaultRekey, for example "prod@~/.ansible/new-pass"
---@field auto_detect? boolean Auto detect vault encrypted files (default: true)
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
  conda_env = nil,
  ansible_vault_path = nil,
  debug = false,
}

---@type AnsibleVaultConfig
M.config = vim.deepcopy(DEFAULT_CONFIG)

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

---@return string[]
local function get_vault_argv()
  local executable = "ansible-vault"
  if is_nonempty_string(M.config.ansible_vault_path) then
    executable = expand_path(M.config.ansible_vault_path)
  end

  if is_nonempty_string(M.config.conda_env) then
    return { "conda", "run", "-n", M.config.conda_env, executable }
  end

  return { executable }
end

---@param action string
---@param args string[]
---@param target? string|false
---@return string[]
local function build_vault_argv(action, args, target)
  local argv = get_vault_argv()
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
  if lines[#lines] == "" then
    table.remove(lines, #lines)
  end
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
local function get_password_args(callback)
  if is_nonempty_string(M.config.password_file) then
    callback({ "--vault-password-file", expand_path(M.config.password_file) })
    return
  end

  local vault_ids = {}
  if type(M.config.vault_ids) == "table" and #M.config.vault_ids > 0 then
    for _, vault_id in ipairs(M.config.vault_ids) do
      if is_nonempty_string(vault_id) then
        table.insert(vault_ids, expand_vault_id(vault_id))
      end
    end
  elseif is_nonempty_string(M.config.vault_id) then
    table.insert(vault_ids, expand_vault_id(M.config.vault_id))
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

  local ok, password = pcall(vim.fn.inputsecret, "Ansible Vault Password: ")
  vim.cmd("redraw")

  if not ok or not password or password == "" then
    vim.notify("Password is required", vim.log.levels.ERROR)
    callback(nil)
    return
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
---@return string[]
local function with_encrypt_vault_id(args)
  local result = vim.deepcopy(args or {})
  if is_nonempty_string(M.config.encrypt_vault_id) then
    table.insert(result, "--encrypt-vault-id")
    table.insert(result, M.config.encrypt_vault_id)
  end
  return result
end

---@param extra_args string[]|nil
---@return string[]
local function with_rekey_target_args(extra_args)
  local args = vim.deepcopy(extra_args or {})
  if has_rekey_target(args) then
    return args
  end

  if is_nonempty_string(M.config.rekey_password_file) then
    table.insert(args, "--new-vault-password-file")
    table.insert(args, expand_path(M.config.rekey_password_file))
  elseif is_nonempty_string(M.config.rekey_vault_id) then
    table.insert(args, "--new-vault-id")
    table.insert(args, expand_vault_id(M.config.rekey_vault_id))
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
local function run_vault(action, input, args, callback)
  local argv = build_vault_argv(action, args or {}, "-")
  local stdout_data = {}
  local stderr_data = {}

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
        local stdout = join_job_data(stdout_data)
        local stderr = join_job_data(stderr_data)

        if exit_code == 0 then
          callback(true, stdout)
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

  vim.fn.chansend(job_id, input)
  vim.fn.chanclose(job_id, "stdin")
end

---@param args string|nil
---@return string[]
local function parse_command_args(args)
  if not is_nonempty_string(args) then
    return {}
  end
  return vim.fn.split(args)
end

---Run ansible-vault against a file path.
---@param action string
---@param file_path string
---@param args string[]
---@param callback fun(success: boolean, output: string): nil
local function run_vault_file(action, file_path, args, callback)
  local argv = build_vault_argv(action, args or {}, file_path)
  local stdout_data = {}
  local stderr_data = {}

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
        local stdout = join_job_data(stdout_data)
        local stderr = join_job_data(stderr_data)

        if exit_code == 0 then
          callback(true, stdout)
          return
        end

        callback(false, stderr ~= "" and stderr or stdout)
      end)
    end,
  })

  if job_id <= 0 then
    callback(false, "Failed to start ansible-vault")
  end
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
---@return boolean
local function replace_buffer_lines(buf, expected_changedtick, output, success_message)
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
  vim.notify(success_message, vim.log.levels.INFO)
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
function M.encrypt(buf)
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

    run_vault("encrypt", content, with_encrypt_vault_id(args), function(success, output)
      run_cleanup(cleanup)
      finish_buffer_operation(target, "encrypt")

      if success then
        replace_buffer_lines(target, tick, output, "Buffer encrypted successfully")
      else
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---Decrypt current buffer.
---@param buf? integer
function M.decrypt(buf)
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
        replace_buffer_lines(target, tick, output, "Buffer decrypted successfully")
      else
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---View encrypted buffer in a floating window.
---@param buf? integer
function M.view(buf)
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
      else
        vim.notify("View failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---@class AnsibleVaultSelection
---@field start_row integer
---@field start_col integer
---@field end_row integer
---@field end_col integer
---@field lines string[]
---@field linewise boolean

---@param buf integer
---@param range_opts? table
---@return AnsibleVaultSelection|nil
local function get_selection(buf, range_opts)
  local start_pos = vim.fn.getpos("'<")
  local end_pos = vim.fn.getpos("'>")
  local start_row = start_pos[2]
  local start_col = start_pos[3]
  local end_row = end_pos[2]
  local end_col = end_pos[3]
  local range_linewise = false

  local has_range = range_opts and range_opts.range and range_opts.range > 0
  local marks_match_range = has_range and start_row == range_opts.line1 and end_row == range_opts.line2
  if has_range and not marks_match_range then
    start_row = range_opts.line1
    end_row = range_opts.line2
    start_col = 1
    local last_line = vim.api.nvim_buf_get_lines(buf, end_row - 1, end_row, false)[1] or ""
    end_col = #last_line
    range_linewise = true
  elseif start_row == 0 or end_row == 0 then
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

  if start_row > end_row or (start_row == end_row and start_col > end_col) then
    start_row, end_row = end_row, start_row
    start_col, end_col = end_col, start_col
  end

  local line_count = vim.api.nvim_buf_line_count(buf)
  start_row = math.max(1, math.min(start_row, line_count))
  end_row = math.max(1, math.min(end_row, line_count))

  local lines = vim.api.nvim_buf_get_lines(buf, start_row - 1, end_row, false)
  if #lines == 0 then
    return nil
  end

  local visual_mode = vim.fn.visualmode()
  local linewise = range_linewise or visual_mode == "V"

  if linewise then
    start_col = 1
    end_col = #lines[#lines]
  else
    if #lines == 1 then
      lines[1] = lines[1]:sub(start_col, end_col)
    else
      lines[1] = lines[1]:sub(start_col)
      lines[#lines] = lines[#lines]:sub(1, end_col)
    end
  end

  return {
    start_row = start_row - 1,
    start_col = start_col - 1,
    end_row = end_row - 1,
    end_col = end_col,
    lines = lines,
    linewise = linewise,
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

---@param buf integer
---@return AnsibleVaultSelection|nil
local function get_plain_yaml_value_under_cursor(buf)
  local row = vim.api.nvim_win_get_cursor(0)[1]
  local line = vim.api.nvim_buf_get_lines(buf, row - 1, row, false)[1] or ""
  local _, key, value = line:match("^(%s*)([%w_.%-]+):%s*(.-)%s*$")

  if not key or value == "" or value:match("^!vault") then
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

  for row = cursor_row, math.max(1, cursor_row - 100), -1 do
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
    local indent, key, value = full_line:match("^(%s*)([%w_.%-]+):%s*(.-)%s*$")
    if key and value ~= "" and not value:match("^!vault") then
      plan.content = value
      plan.name = key
      plan.mode = "full_line"
      plan.indent = indent
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
local function encrypt_string_selection(buf, selection)
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

    local full_args = with_encrypt_vault_id(args)
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

      local ok, err = pcall(
        vim.api.nvim_buf_set_text,
        buf,
        plan.start_row,
        plan.start_col,
        plan.end_row,
        plan.end_col,
        format_encrypt_string_output(output, plan)
      )

      if ok then
        vim.notify("String encrypted successfully", vim.log.levels.INFO)
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
    end)
  end)
end

---Encrypt selected text.
---@param range_opts? table
function M.encrypt_string(range_opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_selection(target, range_opts)

  encrypt_string_selection(target, selection)
end

---Encrypt the plain YAML value under the cursor.
function M.encrypt_string_under_cursor()
  local target = vim.api.nvim_get_current_buf()
  local selection = get_plain_yaml_value_under_cursor(target)

  if not selection then
    vim.notify("No plain YAML key/value found under cursor", vim.log.levels.WARN)
    return
  end

  encrypt_string_selection(target, selection)
end

---Toggle between encrypted and decrypted state.
---@param buf? integer
function M.toggle(buf)
  local target = normalize_buf(buf)
  if M.is_buffer_encrypted(target) then
    M.decrypt(target)
  else
    M.encrypt(target)
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
function M.edit(buf)
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
      vim.api.nvim_buf_set_name(edit_buf, "ansible-vault://" .. original_file)

      vim.b[edit_buf].vault_original_buf = original_buf
      vim.b[edit_buf].vault_original_file = original_file
      vim.b[edit_buf].vault_original_signature = original_signature
      vim.b[edit_buf].vault_password_args = args
      vim.b[edit_buf].vault_cleanup = cleanup
      vim.b[edit_buf].vault_write_pending = false

      if vim.api.nvim_win_is_valid(original_win) then
        vim.api.nvim_win_set_buf(original_win, edit_buf)
      else
        vim.api.nvim_set_current_buf(edit_buf)
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
          local encrypt_args = with_encrypt_vault_id(vim.b[cur_buf].vault_password_args)

          debug_log("VaultEdit: encrypting to %s", orig_file)

          run_vault("encrypt", edit_content, encrypt_args, function(enc_success, enc_output)
            if not is_valid_buf(cur_buf) then
              return
            end

            vim.b[cur_buf].vault_write_pending = false

            if not enc_success then
              vim.notify("Encryption failed: " .. enc_output, vim.log.levels.ERROR)
              return
            end

            if not same_file_signature(orig_signature, file_signature(orig_file)) then
              vim.notify("Original file changed on disk; encrypted output was not written", vim.log.levels.ERROR)
              return
            end

            local write_ok, write_err = atomic_write_file(orig_file, enc_output .. "\n")
            if not write_ok then
              vim.notify("Failed to write encrypted file: " .. write_err, vim.log.levels.ERROR)
              return
            end

            cleanup_edit_buffer(cur_buf)
            close_edit_buffer(cur_buf, orig_buf, orig_file, original_win)
            vim.notify("Encrypted and saved: " .. orig_file, vim.log.levels.INFO)
          end)
        end,
      })

      vim.api.nvim_create_autocmd({ "BufDelete", "BufWipeout" }, {
        buffer = edit_buf,
        callback = function(event)
          cleanup_edit_buffer(event.buf)
          debug_log("VaultEdit: buffer closed")
        end,
      })

      vim.notify("Editing decrypted content. :w encrypts and saves.", vim.log.levels.INFO)
    end)
  end)
end

---Rekey the current encrypted file.
---@param opts? { args?: string[] }
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

    local rekey_args = with_encrypt_vault_id(password_args)
    vim.list_extend(rekey_args, with_rekey_target_args(opts and opts.args or {}))

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

      vim.notify("Vault file rekeyed successfully", vim.log.levels.INFO)
    end)
  end)
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
        local indent = #(line:match("^(%s*)") or "")
        min_indent = math.min(min_indent, indent)
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
        local indent = #(line:match("^(%s*)") or "")
        min_indent = math.min(min_indent, indent)
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
local function format_decrypt_string_output(output, parsed)
  local lines = output_to_lines(output)

  if not parsed.var_name then
    return lines
  end

  local indent = parsed.indent or ""
  if #lines == 1 then
    return { indent .. parsed.var_name .. ": " .. lines[1] }
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
local function decrypt_string_selection(target, selection, mode)
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
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if mode == "view" then
        local title = parsed.var_name and string.format(" %s (read-only) ", parsed.var_name)
          or " Vault String (read-only) "
        open_output_window(output, title, filetype)
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
        vim.notify("String decrypted successfully", vim.log.levels.INFO)
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
    end)
  end)
end

---View selected encrypted string in floating window.
---@param range_opts? table
function M.view_string(range_opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_selection(target, range_opts)
  decrypt_string_selection(target, selection, "view")
end

---Decrypt selected encrypted string in place.
---@param range_opts? table
function M.decrypt_string(range_opts)
  local target = vim.api.nvim_get_current_buf()
  local selection = get_selection(target, range_opts)
  decrypt_string_selection(target, selection, "replace")
end

---View encrypted string under cursor in a floating window.
function M.view_string_under_cursor()
  local target = vim.api.nvim_get_current_buf()
  local selection = find_vault_block_under_cursor(target)
  decrypt_string_selection(target, selection, "view")
end

---Decrypt encrypted string under cursor in place.
function M.decrypt_string_under_cursor()
  local target = vim.api.nvim_get_current_buf()
  local selection = find_vault_block_under_cursor(target)
  decrypt_string_selection(target, selection, "replace")
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

---Setup the plugin.
---@param opts? AnsibleVaultConfig
function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})

  vim.api.nvim_create_user_command("VaultEncrypt", function()
    M.encrypt()
  end, { desc = "Encrypt current buffer with ansible-vault", force = true })

  vim.api.nvim_create_user_command("VaultDecrypt", function()
    M.decrypt()
  end, { desc = "Decrypt current buffer with ansible-vault", force = true })

  vim.api.nvim_create_user_command("VaultView", function()
    M.view()
  end, { desc = "View encrypted buffer in floating window", force = true })

  vim.api.nvim_create_user_command("VaultToggle", function()
    M.toggle()
  end, { desc = "Toggle vault encryption state", force = true })

  vim.api.nvim_create_user_command("VaultEdit", function()
    M.edit()
  end, { desc = "Edit encrypted buffer in a secure scratch buffer", force = true })

  vim.api.nvim_create_user_command("VaultRekey", function(command_opts)
    M.rekey({ args = parse_command_args(command_opts.args) })
  end, { nargs = "*", desc = "Rekey encrypted file with ansible-vault", force = true })

  vim.api.nvim_create_user_command("VaultEncryptString", function(command_opts)
    M.encrypt_string(command_opts)
  end, { range = true, desc = "Encrypt selected string", force = true })

  vim.api.nvim_create_user_command("VaultDecryptString", function(command_opts)
    M.decrypt_string(command_opts)
  end, { range = true, desc = "Decrypt selected string", force = true })

  vim.api.nvim_create_user_command("VaultViewString", function(command_opts)
    M.view_string(command_opts)
  end, { range = true, desc = "View selected encrypted string", force = true })

  vim.api.nvim_create_user_command("VaultEncryptStringUnderCursor", function()
    M.encrypt_string_under_cursor()
  end, { desc = "Encrypt YAML value under cursor", force = true })

  vim.api.nvim_create_user_command("VaultViewStringUnderCursor", function()
    M.view_string_under_cursor()
  end, { desc = "View vault string under cursor", force = true })

  vim.api.nvim_create_user_command("VaultDecryptStringUnderCursor", function()
    M.decrypt_string_under_cursor()
  end, { desc = "Decrypt vault string under cursor", force = true })

  local group = vim.api.nvim_create_augroup(AUGROUP, { clear = true })
  if M.config.auto_detect then
    vim.api.nvim_create_autocmd("BufReadPost", {
      group = group,
      pattern = "*",
      callback = function(event)
        vim.b[event.buf].ansible_vault_encrypted = M.is_buffer_encrypted(event.buf)
      end,
    })
  end
end

M._private = {
  build_vault_argv = build_vault_argv,
  expand_vault_id = expand_vault_id,
  extract_vault_from_yaml = extract_vault_from_yaml,
  get_vault_argv = get_vault_argv,
  parse_vault_from_yaml = parse_vault_from_yaml,
  output_to_lines = output_to_lines,
}

return M
