---The inline `!vault` lifecycle, and working out what a command should act on.
---
---An inline value is a single YAML scalar encrypted in place, in a file that is
---otherwise plain. Everything here exists because that is a different shape from a
---whole-file vault: the key has to survive the round trip, the ciphertext has to
---be indented under it, and only the one value may be touched.
---
---Scope resolution lives here too, because it is the same question asked from the
---other side: given a buffer, a range and a cursor, is this a whole file or one
---inline value? The rule is fixed and reads nothing the user cannot see — in
---particular never the `'<`/`'>` marks, which made the old no-range commands act
---on a stale selection elsewhere in the buffer.
local M = {}

local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local config = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")
local op = require("ansible-vault.op")
local plaintext = require("ansible-vault.plaintext")
local secure = require("ansible-vault.secure")
local ui = require("ansible-vault.ui")
local yaml = require("ansible-vault.yaml")

local notify = config.notify

local parse_vault_from_yaml

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
function M.line_selection(buf, start_row, end_row)
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
function M.block_under_cursor(buf)
  local cursor_row = vim.api.nvim_win_get_cursor(0)[1]
  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)

  local start_row, end_row = yaml.find_block(lines, cursor_row)
  if not start_row then
    return nil
  end

  local selection = M.line_selection(buf, start_row, end_row)
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
function M.resolve_scope(buf, range_opts, want)
  if range_opts and range_opts.range and range_opts.range > 0 then
    local selection = M.line_selection(buf, range_opts.line1, range_opts.line2)
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
    local block = M.block_under_cursor(buf)
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
function M.encrypt_selection(buf, selection, opts)
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
function M.decrypt_selection(target, selection, mode, opts)
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
function M.rekey_selection(target, selection, opts)
  local parsed = parse_vault_selection(selection)
  if not parsed then
    return
  end

  if not parsed.var_name then
    vim.notify("Cannot rekey a vault block with no YAML key to put it back under", vim.log.levels.ERROR)
    return
  end

  local effective = config.effective(opts)
  local new_args, new_err = credentials.rekey_args(effective, { header_label = parsed.header and parsed.header.label })
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

return M
