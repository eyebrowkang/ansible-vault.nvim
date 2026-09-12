local ansible_cfg = require("ansible-vault.ansible_cfg")
local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local edit_mod = require("ansible-vault.edit")
local config_mod = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")
local op = require("ansible-vault.op")
local plaintext = require("ansible-vault.plaintext")
local secure = require("ansible-vault.secure")
local ui = require("ansible-vault.ui")
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
local parse_vault_from_yaml

---The live configuration table. Callers hold this reference, so `setup()` fills
---it in place rather than replacing it.
---@type AnsibleVaultConfig
M.config = config_mod.values

---Parse the `$ANSIBLE_VAULT` header of some content.
M.parse_header = buffer.parse_header

---Whether some content is vault ciphertext.
M.is_encrypted = buffer.is_encrypted

---Whether a buffer holds vault ciphertext. The supported way to drive a
---statusline: it inspects the buffer rather than reading state an earlier
---operation happened to leave behind.
M.is_buffer_encrypted = buffer.is_buffer_encrypted

---Edit an encrypted file in a secure scratch buffer.
M.edit = edit_mod.edit

local is_nonempty_string = config_mod.is_nonempty_string
local effective_config = config_mod.effective
local notify = config_mod.notify

local expand_path = credentials.expand_path

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

---@param target integer
---@param opts? table
local function encrypt_file(target, opts)
  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.is_valid(target) then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if not buffer.start_operation(target, "encrypt") then
      buffer.run_cleanup(creds.cleanup)
      return
    end

    local tick = buffer.changedtick(target)
    local content = buffer.content(target)
    local args = op.with_encrypt_vault_id(creds.args, opts, creds, context)

    cli.run("encrypt", content, args, function(success, output)
      buffer.run_cleanup(creds.cleanup)
      buffer.finish_operation(target, "encrypt")

      if success then
        if buffer.replace_lines(target, tick, output, "Buffer encrypted successfully") then
          plaintext.leave(target)
          op.emit("encrypt", "file", { buf = target })
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
  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.is_valid(target) then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if not buffer.start_operation(target, "decrypt") then
      buffer.run_cleanup(creds.cleanup)
      return
    end

    local tick = buffer.changedtick(target)
    local content = buffer.content(target)

    cli.run("decrypt", content, creds.args, function(success, output)
      buffer.run_cleanup(creds.cleanup)
      buffer.finish_operation(target, "decrypt")

      if success then
        if buffer.replace_lines(target, tick, output, "Buffer decrypted successfully") then
          plaintext.enter(target, "file", opts)
          op.emit("decrypt", "file", { buf = target })
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
  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.is_valid(target) then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    cli.run("decrypt", buffer.content(target), creds.args, function(success, output)
      buffer.run_cleanup(creds.cleanup)

      if success then
        ui.open_float(output, " Vault View (read-only) ", filetype)
        op.emit("view", "file", { buf = target })
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
  local mode = plaintext.mode(buf)
  if mode == "file" then
    return { scope = "file", state = "plaintext" }, nil
  end

  if buffer.is_buffer_encrypted(buf) then
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
  local planned_tick = buffer.changedtick(buf)
  local context = buffer.capture_context(buf)

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.is_valid(buf) then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if buffer.changedtick(buf) ~= planned_tick then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Buffer changed before encryption started; result was not applied", vim.log.levels.ERROR)
      return
    end

    if not buffer.start_operation(buf, "encrypt_string") then
      buffer.run_cleanup(creds.cleanup)
      return
    end

    local full_args = op.with_encrypt_vault_id(creds.args, opts, creds, context)
    table.insert(full_args, "--stdin-name")
    table.insert(full_args, plan.name)

    cli.run("encrypt_string", plan.content, full_args, function(success, output)
      buffer.run_cleanup(creds.cleanup)
      buffer.finish_operation(buf, "encrypt_string")

      if not success then
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if not buffer.is_valid(buf) then
        vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if buffer.changedtick(buf) ~= planned_tick then
        vim.notify("Vault operation finished, but the buffer changed; result was not applied", vim.log.levels.ERROR)
        return
      end

      local ok, err = replace_selection_text(buf, selection, format_encrypt_string_output(output, plan))

      if ok then
        notify("String encrypted successfully", vim.log.levels.INFO)
        op.emit("encrypt", "inline", { buf = buf, name = plan.name })
      else
        vim.notify("Failed to update selection: " .. err, vim.log.levels.ERROR)
      end
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

  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end

    -- Old credentials open the file; the new identity is named separately. No
    -- --encrypt-vault-id: on `rekey` that flag selects from a pool seeded with
    -- the OLD identities, so it can silently re-encrypt with the old password.
    -- See credentials.rekey_args.
    local new_args, new_err = credentials.rekey_args(effective_config(opts), context)
    if new_err then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("VaultRekey: " .. new_err, vim.log.levels.ERROR)
      return
    end
    if not new_args then
      buffer.run_cleanup(creds.cleanup)
      vim.notify(
        "VaultRekey requires new_vault_id, new_password_file, or a --new-vault-* argument",
        vim.log.levels.ERROR
      )
      return
    end

    local rekey_args = vim.deepcopy(creds.args)
    vim.list_extend(rekey_args, new_args)

    if not buffer.start_operation(target, "rekey") then
      buffer.run_cleanup(creds.cleanup)
      return
    end

    cli.run_file("rekey", file_path, rekey_args, function(success, output)
      buffer.run_cleanup(creds.cleanup)
      buffer.finish_operation(target, "rekey")

      if not success then
        vim.notify("Rekey failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if buffer.is_valid(target) then
        pcall(vim.api.nvim_buf_call, target, function()
          vim.cmd("silent! edit!")
        end)
        buffer.remember_header(target)
      end

      notify("Vault file rekeyed successfully", vim.log.levels.INFO)
      op.emit("rekey", "file", { buf = target, file = file_path })
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

  local planned_tick = buffer.changedtick(target)
  local filetype = vim.bo[target].filetype
  local context = buffer.capture_context(target)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.is_valid(target) then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    if mode == "replace" and not buffer.start_operation(target, "decrypt_string") then
      buffer.run_cleanup(creds.cleanup)
      return
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(success, output)
      buffer.run_cleanup(creds.cleanup)
      if mode == "replace" then
        buffer.finish_operation(target, "decrypt_string")
      end

      if not success then
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if mode == "view" then
        local title = parsed.var_name and string.format(" %s (read-only) ", parsed.var_name)
          or " Vault String (read-only) "
        ui.open_float(output:gsub("\n$", ""), title, filetype)
        return
      end

      if not buffer.is_valid(target) then
        vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if buffer.changedtick(target) ~= planned_tick then
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
        plaintext.track_region(target, selection.start_row, selection.start_row + #replacement - 1, parsed)
        plaintext.enter(target, "inline", opts)
        notify("String decrypted successfully", vim.log.levels.INFO)
        op.emit("decrypt", "inline", { buf = target, name = parsed.var_name })
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

  local planned_tick = buffer.changedtick(target)
  local context = buffer.capture_context(target)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.start_operation(target, "rekey") then
      buffer.run_cleanup(creds.cleanup)
      return
    end

    local function finish()
      buffer.run_cleanup(creds.cleanup)
      buffer.finish_operation(target, "rekey")
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(ok, output)
      if not ok then
        finish()
        vim.notify("Rekey failed to decrypt the value: " .. output, vim.log.levels.ERROR)
        return
      end

      -- Strip the trailing newline ansible-vault adds, so re-encrypting does not
      -- grow the value by a blank line on every rekey.
      local content = output:gsub("\n$", "")

      local args = vim.deepcopy(encrypt_args)
      vim.list_extend(args, { "--stdin-name", parsed.var_name })

      cli.run("encrypt_string", content, args, function(enc_ok, enc_output)
        finish()

        if not enc_ok then
          -- Nothing was written, so the block is still there under its old key.
          vim.notify("Rekey failed to re-encrypt the value: " .. enc_output, vim.log.levels.ERROR)
          return
        end

        if not buffer.is_valid(target) or buffer.changedtick(target) ~= planned_tick then
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
        op.emit("rekey", "inline", { buf = target, name = parsed.var_name })
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
  local target = buffer.normalize(buf)
  if not buffer.is_valid(target) then
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
    plaintext.restore_regions(target, opts, function(ok)
      if not ok then
        return
      end
      plaintext.leave(target)
      notify("Vault values restored", vim.log.levels.INFO)
      op.emit("encrypt", "inline", { buf = target })
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

  plaintext.enter(buf, "file", opts)
  op.emit("create", "file", { buf = buf, file = path })
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
        plaintext.leave(event.buf)
      end
    end,
  })
end

return M
