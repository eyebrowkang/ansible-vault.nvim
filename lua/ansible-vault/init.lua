local ansible_cfg = require("ansible-vault.ansible_cfg")
local cli = require("ansible-vault.cli")
local config_mod = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")
local fs = require("ansible-vault.fs")
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
local NAMESPACE = vim.api.nvim_create_namespace("ansible-vault")
local parse_vault_from_yaml
local write_plaintext_buffer
local restore_inline_regions
local leave_plaintext_mode
local remember_header

---The live configuration table. Callers hold this reference, so `setup()` fills
---it in place rather than replacing it.
---@type AnsibleVaultConfig
M.config = config_mod.values

local is_nonempty_string = config_mod.is_nonempty_string
local effective_config = config_mod.effective
local notify = config_mod.notify

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

local expand_path = credentials.expand_path

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
---Parse command arguments into config overrides.
---
---Credential flags are spelled exactly as `ansible-vault` spells them, and an
---unrecognised one is an error rather than a silently ignored positional: a typo
---like `--vault-pasword-file` used to fall through to an interactive prompt,
---which looks like the credential simply was not found.
---@return table|nil parsed, string|nil err
local function parse_operation_options(args, opts)
  local result = {
    overrides = {},
    positionals = {},
  }

  -- A command-line credential replaces the configured ones outright rather than
  -- adding to them; `false` is the sentinel `effective_config` reads as "unset".
  local function exclusive(key)
    for _, other in ipairs({ "password_files", "vault_ids", "ask_password" }) do
      if other ~= key and result.overrides[other] == nil then
        result.overrides[other] = false
      end
    end
  end

  local index = 1
  while index <= #(args or {}) do
    local arg = args[index]
    local next_arg = args[index + 1]

    if arg == "--vault-password-file" and next_arg then
      exclusive("password_files")
      result.overrides.password_files = result.overrides.password_files or {}
      table.insert(result.overrides.password_files, next_arg)
      index = index + 2
    elseif arg == "--vault-id" and next_arg then
      exclusive("vault_ids")
      result.overrides.vault_ids = result.overrides.vault_ids or {}
      table.insert(result.overrides.vault_ids, next_arg)
      index = index + 2
    elseif arg == "--ask-vault-password" then
      exclusive("ask_password")
      result.overrides.ask_password = true
      index = index + 1
    elseif arg == "--encrypt-vault-id" and next_arg then
      result.overrides.encrypt_vault_id = next_arg
      index = index + 2
    elseif arg == "--new-vault-password-file" and next_arg then
      result.overrides.new_password_file = next_arg
      result.overrides.new_vault_id = false
      index = index + 2
    elseif arg == "--new-vault-id" and next_arg then
      result.overrides.new_vault_id = next_arg
      result.overrides.new_password_file = false
      index = index + 2
    elseif arg:match("^%-") then
      return nil, string.format("unknown or incomplete argument: %s", arg)
    elseif opts and opts.positionals then
      table.insert(result.positionals, arg)
      index = index + 1
    else
      return nil, string.format("unexpected argument: %s", arg)
    end
  end

  return result, nil
end

---@param arg_lead string
---@param include_rekey? boolean
---@param include_labels? boolean
---@return string[]
local function complete_operation_args(arg_lead, include_rekey, include_labels)
  local candidates = {
    "--vault-id",
    "--vault-password-file",
    "--ask-vault-password",
    "--encrypt-vault-id",
  }

  if include_rekey then
    table.insert(candidates, "--new-vault-password-file")
    table.insert(candidates, "--new-vault-id")
  end

  if include_labels then
    for _, vault_id in ipairs(credentials.as_list(M.config.vault_ids)) do
      local label = vault_id:match("^([^@]+)@")
      if label then
        table.insert(candidates, label)
      end
    end
  end

  return vim.tbl_filter(function(candidate)
    return vim.startswith(candidate, arg_lead)
  end, candidates)
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

  local lines = cli.output_to_lines(output)
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
  notify(success_message, vim.log.levels.INFO)
  return true
end

---@param output string
---@param title string
---@param filetype? string
local function open_output_window(output, title, filetype)
  -- Explicitly hardened rather than relying on the implicit scratch defaults;
  -- this window shows decrypted content.
  local buf = secure.create_buffer(false, true)
  local lines = cli.output_to_lines(output)
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

  -- Deliberately no else branch. This runs again once the buffer holds plaintext,
  -- and that content has no header to read a label from; keeping the last one
  -- seen is exactly what lets `:VaultDecrypt` + `:VaultEncrypt` put the 1.2 label
  -- back instead of silently rewriting the file as 1.1.
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

---Which kind of plaintext a buffer is currently holding, if any.
---@param buf integer
---@return "file"|"inline"|nil
local function plaintext_mode(buf)
  if not is_valid_buf(buf) then
    return nil
  end
  return vim.b[buf].ansible_vault_plaintext
end

---@param buf integer
---@param mode "file"|"inline"
---@param opts? table
local function enter_plaintext_mode(buf, mode, opts)
  if not is_valid_buf(buf) then
    return
  end

  secure.protect(buf)

  if plaintext_mode(buf) then
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

---@param target integer
---@param opts? table
local function encrypt_file(target, opts)
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

    cli.run("encrypt", content, args, function(success, output)
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

---@param target integer
---@param opts? table
local function decrypt_file(target, opts)
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

    cli.run("decrypt", content, creds.args, function(success, output)
      run_cleanup(creds.cleanup)
      finish_buffer_operation(target, "decrypt")

      if success then
        if replace_buffer_lines(target, tick, output, "Buffer decrypted successfully", opts) then
          enter_plaintext_mode(target, "file", opts)
          emit_event("decrypt", "file", { buf = target })
        end
      else
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---@param target integer
---@param opts? table
local function view_file(target, opts)
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

    cli.run("decrypt", buffer_content(target), creds.args, function(success, output)
      run_cleanup(creds.cleanup)

      if success then
        open_output_window(output, " Vault View (read-only) ", filetype)
        emit_event("view", "file", { buf = target })
      else
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

---A whole-line region of a buffer.
---
---Line-based on purpose. The previous charwise and blockwise handling read the
---`'<`/`'>` marks when no range was given, which meant a command run from normal
---mode silently operated on the last visual selection anywhere in the buffer.
---A `[range]` is always supplied by Neovim for the command forms, so the marks are
---never needed.
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

---Work out what a command should act on.
---
---One rule, applied in order, so the answer never depends on editor state the
---user cannot see — in particular it never reads the `'<`/`'>` marks, which made
---the old no-range commands act on a stale selection elsewhere in the buffer:
---
---  1. an explicit `[range]`    -> those lines, as an inline value
---  2. the buffer is mid-edit   -> whatever it was decrypted as
---  3. line 1 is a vault header -> the whole file
---  4. looking for ciphertext   -> the `!vault` block under the cursor
---  5. looking for plaintext    -> the whole buffer
---
---Step 3 must come before step 4: `yaml.find_block` accepts a bare
---`$ANSIBLE_VAULT` line as the start of a block, so a whole-file vault would
---otherwise resolve as an inline value.
---
---`want` is why steps 4 and 5 differ. Hunting for a `!vault` block under the
---cursor is safe, because the shape is unmistakable. Hunting for a plain
---`key: value` line is not: in a YAML file almost every line is one, so
---`:VaultEncrypt` would encrypt whichever line the cursor happened to be on
---instead of the file. Encrypting one value therefore asks for a range —
---`:.VaultEncrypt` for the current line.
---@param buf integer
---@param range_opts? table
---@param want "ciphertext"|"plain"
---@return { scope: "file"|"inline", state: "ciphertext"|"plaintext"|"plain", selection?: AnsibleVaultSelection }|nil
---@return string|nil err
local function resolve_scope(buf, range_opts, want)
  if range_opts and range_opts.range and range_opts.range > 0 then
    local selection = get_line_selection(buf, range_opts.line1, range_opts.line2)
    if not selection then
      return nil, "the given range is empty"
    end
    local state = parse_vault_from_yaml(table.concat(selection.lines, "\n")) and "ciphertext" or "plain"
    return { scope = "inline", state = state, selection = selection }, nil
  end

  -- "file" mode means the whole buffer is plaintext, so there is nothing else to
  -- look for. "inline" mode does not: the buffer is ordinary YAML with some values
  -- decrypted, and the others are still encrypted and still addressable.
  local mode = plaintext_mode(buf)
  if mode == "file" then
    return { scope = "file", state = "plaintext" }, nil
  end

  if M.is_buffer_encrypted(buf) then
    return { scope = "file", state = "ciphertext" }, nil
  end

  if want == "ciphertext" then
    local block = find_vault_block_under_cursor(buf)
    if block then
      return { scope = "inline", state = "ciphertext", selection = block }, nil
    end
    if mode == "inline" then
      return { scope = "inline", state = "plaintext" }, nil
    end
    return nil,
      "nothing encrypted here: this buffer is not an Ansible Vault file, and the cursor "
        .. "is not inside a !vault block. Give a [range] to name one."
  end

  if mode == "inline" then
    return { scope = "inline", state = "plaintext" }, nil
  end

  return { scope = "file", state = "plain" }, nil
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

  -- A single line that is a `key: value` pair keeps its key, and only the value
  -- is encrypted. That is what makes `:VaultEncrypt` on such a line produce
  -- valid YAML rather than encrypting the key along with it.
  local full_line = vim.api.nvim_buf_get_lines(buf, selection.start_row, selection.start_row + 1, false)[1] or ""
  local indent, key, value = extract_yaml_key_value(full_line)
  if key and value and value ~= "" then
    plan.content = value
    plan.name = key
    plan.mode = "full_line"
    plan.indent = indent or ""
  end

  return plan
end

---@param output string
---@param plan table
---@return string[]
local function format_encrypt_string_output(output, plan)
  local lines = cli.output_to_lines(output)

  -- ansible-vault terminates its output with a newline; splicing that in as-is
  -- would leave a stray blank line behind in the buffer.
  while #lines > 1 and lines[#lines] == "" do
    table.remove(lines, #lines)
  end

  if plan.mode == "full_line" and plan.indent ~= "" then
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

    cli.run("encrypt_string", plan.content, full_args, function(success, output)
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
        notify("String encrypted successfully", vim.log.levels.INFO)
        emit_event("encrypt", "inline", { buf = buf, name = plan.name })
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

--- Inline region tracking -------------------------------------------------
---
---After decrypting one inline value, the buffer holds that plaintext inside an
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

      -- The extmark is left-gravity, so deleting the decrypted lines collapses it
      -- onto whatever follows. Without this check the next value down would be
      -- read as the region's content and replaced with a !vault block — encrypting
      -- something the user never decrypted. Skip instead, and say so.
      if #lines == 0 or (region.name and name ~= region.name) then
        vim.notify(
          string.format(
            "The decrypted value for '%s' is no longer there; it was not re-encrypted",
            region.name or "an inline value"
          ),
          vim.log.levels.WARN
        )
        step()
        return
      end

      local args = with_encrypt_vault_id(
        creds.args,
        opts,
        creds,
        vim.tbl_extend("force", context, { header_label = region.label or context.header_label })
      )
      table.insert(args, "--stdin-name")
      table.insert(args, name or "encrypted_string")

      cli.run("encrypt_string", content, args, function(success, output)
        if not success then
          run_cleanup(creds.cleanup)
          vim.notify("Failed to re-encrypt " .. (name or "value") .. ": " .. output, vim.log.levels.ERROR)
          callback(false)
          return
        end

        local out_lines = cli.output_to_lines(output)
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
    local budget = cli.timeout_ms > 0 and cli.timeout_ms or 30000
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

      local write_ok, write_err = fs.atomic_write(path, body)
      if not write_ok then
        vim.notify("Failed to write file: " .. tostring(write_err), vim.log.levels.ERROR)
        finish(false)
        return
      end

      leave_plaintext_mode(buf)
      notify("Vault values restored and saved: " .. path, vim.log.levels.INFO)
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

    cli.run("encrypt", content, args, function(success, output)
      run_cleanup(creds.cleanup)

      if not success then
        vim.notify("Encryption failed, nothing was written: " .. output, vim.log.levels.ERROR)
        finish(false)
        return
      end

      local write_ok, write_err = fs.atomic_write(path, output)
      if not write_ok then
        vim.notify("Failed to write encrypted file: " .. tostring(write_err), vim.log.levels.ERROR)
        finish(false)
        return
      end

      notify("Encrypted and saved: " .. path, vim.log.levels.INFO)
      emit_event("save", "file", { buf = buf, file = path })
      finish(true)
    end, opts, creds)
  end, opts, context)

  await()
end

---Credentials held for the lifetime of a `:VaultEdit` scratch buffer.
---
---Module-local rather than in `vim.b`. An interactive password reaches the child
---through `creds.env`, so putting `creds` in a buffer variable made it readable
---with `:echo b:vault_creds` for as long as the buffer was open. It also meant
---round-tripping `creds.cleanup`, a closure, through Neovim's variable store.
---@type table<integer, { creds: table, context: table }>
local edit_sessions = {}

---@param edit_buf integer
local function cleanup_edit_buffer(edit_buf)
  local session = edit_sessions[edit_buf]
  if not session then
    return
  end
  edit_sessions[edit_buf] = nil

  if session.creds and session.creds.cleanup then
    session.creds.cleanup()
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
---@param opts? table
function M.edit(buf, opts)
  local original_buf = normalize_buf(buf)
  if opts and opts.range and opts.range > 0 then
    vim.notify("VaultEdit works on a whole vault file; use :VaultDecrypt on an inline value", vim.log.levels.ERROR)
    return
  end
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
  local original_signature = fs.signature(original_file)

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

    cli.run("decrypt", buffer_content(original_buf), creds.args, function(success, output)
      if not success then
        run_cleanup(creds.cleanup)
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
      local decrypted_lines = cli.output_to_lines(output)
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
      edit_sessions[edit_buf] = { creds = creds, context = context }
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
          local session = edit_sessions[cur_buf]
          if not session then
            vim.b[cur_buf].vault_write_pending = false
            vim.notify("No vault session for this buffer; reopen it with :VaultEdit", vim.log.levels.ERROR)
            return
          end
          local edit_creds = session.creds
          local encrypt_args = with_encrypt_vault_id(edit_creds.args, opts, edit_creds, session.context)

          -- 'modified' stays set until the write actually lands. Clearing it up
          -- front would let `:q` wipe the buffer, and its plaintext, while the
          -- encryption is still in flight.
          cli.run("encrypt", edit_content, encrypt_args, function(enc_success, enc_output)
            if not enc_success then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Encryption failed: " .. enc_output, vim.log.levels.ERROR)
              return
            end

            if not fs.same_signature(orig_signature, fs.signature(orig_file)) then
              if is_valid_buf(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Original file changed on disk; encrypted output was not written", vim.log.levels.ERROR)
              return
            end

            local write_ok, write_err = fs.atomic_write(orig_file, enc_output)
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

            notify("Encrypted and saved: " .. orig_file, vim.log.levels.INFO)
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
        end,
      })

      notify("Editing decrypted content. :w encrypts and saves.", vim.log.levels.INFO)
      emit_event("edit", "file", { buf = edit_buf, original_buf = original_buf, file = original_file })
    end, opts, creds)
  end, opts, context)
end

---@param target integer
---@param opts? table
local function rekey_file(target, opts)
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

    -- Old credentials open the file; the new identity is named separately. No
    -- --encrypt-vault-id: on `rekey` that flag selects from a pool seeded with
    -- the OLD identities, so it can silently re-encrypt with the old password.
    -- See credentials.rekey_args.
    local new_args, new_err = credentials.rekey_args(effective_config(opts), context)
    if new_err then
      run_cleanup(creds.cleanup)
      vim.notify("VaultRekey: " .. new_err, vim.log.levels.ERROR)
      return
    end
    if not new_args then
      run_cleanup(creds.cleanup)
      vim.notify(
        "VaultRekey requires new_vault_id, new_password_file, or a --new-vault-* argument",
        vim.log.levels.ERROR
      )
      return
    end

    local rekey_args = vim.deepcopy(creds.args)
    vim.list_extend(rekey_args, new_args)

    if not start_buffer_operation(target, "rekey") then
      run_cleanup(creds.cleanup)
      return
    end

    cli.run_file("rekey", file_path, rekey_args, function(success, output)
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

      notify("Vault file rekeyed successfully", vim.log.levels.INFO)
      emit_event("rekey", "file", { buf = target, file = file_path })
    end, opts, creds)
  end, opts, context)
end

---Parse vault content from YAML format, removing indentation.
---@param content string
---@return table|nil
parse_vault_from_yaml = function(content)
  return yaml.parse_block(content)
end

local yaml_quote_value = yaml.quote_value

---@param output string
---@param parsed table
---@return string[]
local function format_decrypt_string_output(output, parsed)
  local lines = cli.output_to_lines(output)
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

    cli.run("decrypt", parsed.vault_content, creds.args, function(success, output)
      run_cleanup(creds.cleanup)
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
        notify("String decrypted successfully", vim.log.levels.INFO)
        emit_event("decrypt", "inline", { buf = target, name = parsed.var_name })
      else
        vim.notify("Failed to update selection: " .. tostring(err), vim.log.levels.ERROR)
      end
    end, opts, creds)
  end, opts, context)
end

---Rekey a single inline `!vault` value.
---
---`ansible-vault rekey` only takes file paths, so the only way to rotate one
---inline value is decrypt-with-old then encrypt_string-with-new. That means the
---plaintext does briefly exist in this process — but only as a local in this
---function. It is never put in a buffer, a buffer variable, a notification or an
---event payload, so none of the paths that could persist it are involved.
---
---Unlike whole-file rekey, `--encrypt-vault-id` IS correct on the encrypt side:
---`encrypt_string` builds its secret pool from the vault ids actually passed to
---it, so naming the label there selects the new identity rather than an old one.
---@param target integer
---@param selection AnsibleVaultSelection
---@param opts? table
local function rekey_inline(target, selection, opts)
  local parsed = parse_vault_selection(selection)
  if not parsed then
    return
  end

  if not parsed.var_name then
    vim.notify("Cannot rekey a vault block with no YAML key to put it back under", vim.log.levels.ERROR)
    return
  end

  local config = effective_config(opts)
  local new_args, new_err = credentials.rekey_args(config, { header_label = parsed.header and parsed.header.label })
  if new_err then
    vim.notify("VaultRekey: " .. new_err, vim.log.levels.ERROR)
    return
  end
  if not new_args then
    vim.notify("VaultRekey requires new_vault_id, new_password_file, or a --new-vault-* argument", vim.log.levels.ERROR)
    return
  end

  -- `credentials.rekey_args` speaks rekey's flag names; encrypt_string wants the
  -- same identity as a plain --vault-id, plus the label to encrypt with.
  local new_identity = new_args[1] == "--new-vault-id" and new_args[2] or nil
  local encrypt_args = {}
  if new_identity then
    local label = new_identity:match("^([^@]+)@")
    vim.list_extend(encrypt_args, { "--vault-id", new_identity })
    if label then
      vim.list_extend(encrypt_args, { "--encrypt-vault-id", label })
    end
  else
    vim.list_extend(encrypt_args, { "--vault-password-file", new_args[2] })
  end

  local planned_tick = changedtick(target)
  local context = buffer_context(target)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  get_credentials(function(creds)
    if not creds then
      return
    end

    if not start_buffer_operation(target, "rekey") then
      run_cleanup(creds.cleanup)
      return
    end

    local function finish()
      run_cleanup(creds.cleanup)
      finish_buffer_operation(target, "rekey")
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(ok, plaintext)
      if not ok then
        finish()
        vim.notify("Rekey failed to decrypt the value: " .. plaintext, vim.log.levels.ERROR)
        return
      end

      -- Strip the trailing newline ansible-vault adds, so re-encrypting does not
      -- grow the value by a blank line on every rekey.
      local content = plaintext:gsub("\n$", "")

      local args = vim.deepcopy(encrypt_args)
      vim.list_extend(args, { "--stdin-name", parsed.var_name })

      cli.run("encrypt_string", content, args, function(enc_ok, enc_output)
        finish()

        if not enc_ok then
          -- Nothing was written, so the block is still there under its old key.
          vim.notify("Rekey failed to re-encrypt the value: " .. enc_output, vim.log.levels.ERROR)
          return
        end

        if not is_valid_buf(target) or changedtick(target) ~= planned_tick then
          vim.notify("Buffer changed during rekey; the value was left alone", vim.log.levels.ERROR)
          return
        end

        local replacement = format_encrypt_string_output(enc_output, {
          mode = "full_line",
          name = parsed.var_name,
          indent = (parsed.indent or "") .. (parsed.dash and parsed.dash:gsub(".", " ") or ""),
        })

        local replaced, err = replace_selection_text(target, selection, replacement)
        if not replaced then
          vim.notify("Failed to update the value: " .. tostring(err), vim.log.levels.ERROR)
          return
        end

        notify("Inline value rekeyed successfully", vim.log.levels.INFO)
        emit_event("rekey", "inline", { buf = target, name = parsed.var_name })
      end, opts, creds)
    end, opts, creds)
  end, opts, context)
end

--- Scope-aware verbs -------------------------------------------------------
---
---One command per verb, acting on whatever the buffer, the range and the cursor
---say it should act on. The alternative — a separate command per verb for the
---selection and for the cursor — meant three commands for one idea, and made the
---no-range forms read the `'<`/`'>` marks, which silently pointed at an old
---selection somewhere else in the buffer.

---@param buf? integer
---@param opts? table
---@param want "ciphertext"|"plain"
---@return integer|nil target, table|nil scope
local function target_and_scope(buf, opts, want)
  local target = normalize_buf(buf)
  if not is_valid_buf(target) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return nil, nil
  end

  local scope, err = resolve_scope(target, opts, want)
  if not scope then
    vim.notify(err, vim.log.levels.ERROR)
    return nil, nil
  end

  return target, scope
end

---Encrypt the whole buffer, or one inline YAML value.
---@param buf? integer
---@param opts? table
function M.encrypt(buf, opts)
  local target, scope = target_and_scope(buf, opts, "plain")
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
    encrypt_file(target, opts)
    return
  end

  if scope.state == "plaintext" then
    -- The inverse of decrypting in place: fold the tracked regions back into
    -- `!vault` blocks without touching the file. `:w` remains the user's call.
    restore_inline_regions(target, opts, function(ok)
      if not ok then
        return
      end
      leave_plaintext_mode(target)
      notify("Vault values restored", vim.log.levels.INFO)
      emit_event("encrypt", "inline", { buf = target })
    end)
    return
  end

  encrypt_string_selection(target, scope.selection, opts)
end

---Decrypt the whole buffer, or one inline YAML value, in place.
---@param buf? integer
---@param opts? table
function M.decrypt(buf, opts)
  local target, scope = target_and_scope(buf, opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify(
      scope.state == "plaintext" and "Already decrypted" or "Nothing encrypted here to decrypt",
      vim.log.levels.WARN
    )
    return
  end

  if scope.scope == "file" then
    decrypt_file(target, opts)
  else
    decrypt_string_selection(target, scope.selection, "replace", opts)
  end
end

---Show the decrypted content of the buffer, or of one inline value, read-only.
---@param buf? integer
---@param opts? table
function M.view(buf, opts)
  local target, scope = target_and_scope(buf, opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify("Nothing encrypted here to view", vim.log.levels.WARN)
    return
  end

  if scope.scope == "file" then
    view_file(target, opts)
  else
    decrypt_string_selection(target, scope.selection, "view", opts)
  end
end

---Rekey the vault file, or one inline `!vault` value.
---@param opts? table
function M.rekey(opts)
  local target, scope = target_and_scope(nil, opts, "ciphertext")
  if not target then
    return
  end

  if scope.state ~= "ciphertext" then
    vim.notify(
      scope.state == "plaintext" and "Write or discard the decrypted content before rekeying"
        or "Nothing encrypted here to rekey",
      vim.log.levels.ERROR
    )
    return
  end

  if scope.scope == "file" then
    rekey_file(target, opts)
  else
    rekey_inline(target, scope.selection, opts)
  end
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

---Drop every secret this process is still holding. Runs on exit.
---
---Interactive passwords are not cached, so this sweeps the temp password files
---the askpass fallback may have written.
function M.cleanup()
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
    desc = "Encrypt the buffer, or the inline !vault value in [range] or under the cursor",
    complete = "labels",
    range = true,
    run = function(_, parsed)
      M.encrypt(nil, parsed)
    end,
  },
  {
    name = "VaultDecrypt",
    desc = "Decrypt the buffer, or one inline !vault value, in place",
    complete = "operation",
    range = true,
    run = function(_, parsed)
      M.decrypt(nil, parsed)
    end,
  },
  {
    name = "VaultView",
    desc = "Show decrypted content read-only, for the buffer or one inline value",
    complete = "operation",
    range = true,
    run = function(_, parsed)
      M.view(nil, parsed)
    end,
  },
  {
    name = "VaultEdit",
    desc = "Edit an encrypted file in a secure scratch buffer",
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
    parse = { positionals = true },
    run = function(cmd_opts, parsed)
      parsed.bang = cmd_opts.bang
      M.create(parsed)
    end,
  },
  {
    name = "VaultRekey",
    desc = "Rekey the vault file, or one inline !vault value",
    complete = "rekey",
    range = true,
    run = function(_, parsed)
      M.rekey(parsed)
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
    M.setup({})
  end
end

---Register every user command. Idempotent.
function M.register_commands()
  for _, command in ipairs(COMMANDS) do
    vim.api.nvim_create_user_command(command.name, function(cmd_opts)
      ensure_configured()
      local parsed, err = parse_operation_options(parse_command_args(cmd_opts.args), command.parse)
      if not parsed then
        vim.notify(string.format(":%s: %s", command.name, err), vim.log.levels.ERROR)
        return
      end
      -- Scope resolution reads these, so they travel with the overrides rather
      -- than being recovered from editor state later.
      parsed.range = cmd_opts.range
      parsed.line1 = cmd_opts.line1
      parsed.line2 = cmd_opts.line2
      command.run(cmd_opts, parsed)
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
  opts = opts or {}

  local errors = config_mod.validate(opts)
  if #errors > 0 then
    vim.notify("ansible-vault.nvim setup: " .. table.concat(errors, "; "), vim.log.levels.ERROR)
    return
  end

  config_mod.apply(opts)
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
end

return M
