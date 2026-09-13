---The inline `!vault` lifecycle, and working out what a command should act on.
---
---An inline value is a single YAML scalar encrypted in place, in a file that is
---otherwise plain. Everything here exists because that is a different shape from a
---whole-file vault: the key, its indentation and its list dash have to survive the
---round trip, the ciphertext has to be indented under it, and only that one value
---may be touched.
---
---Scope resolution lives here too, because it is the same question asked from the
---other side: given a buffer, a range and a cursor, is this a whole file or one
---inline value? The rule reads nothing the user cannot see — in particular never
---the `'<`/`'>` marks, which made the old no-range commands act on a stale
---selection elsewhere in the buffer. And `:VaultEncrypt` without a range is always
---the whole buffer, never "whatever the cursor is near": in a YAML file almost
---every line looks like a value, so guessing there would encrypt the wrong one.
local M = {}

local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local op = require("ansible-vault.op")
local plaintext = require("ansible-vault.plaintext")
local secure = require("ansible-vault.secure")
local ui = require("ansible-vault.ui")
local yaml = require("ansible-vault.yaml")

---@class AnsibleVaultRegion
---@field start_row integer 1-based, inclusive
---@field end_row integer 1-based, inclusive
---@field lines string[]
---@field parsed table|nil Set when the region is a `!vault` block

---Whole lines, always.
---
---A vault value occupies whole lines once it is encrypted, and a partial-line
---selection could only ever produce invalid YAML, so charwise and blockwise
---selections are deliberately not a concept here.
---@param buf integer
---@param start_row integer 1-based
---@param end_row integer 1-based
---@return AnsibleVaultRegion|nil
function M.line_region(buf, start_row, end_row)
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

  return { start_row = start_row, end_row = end_row, lines = lines }
end

---The `!vault` block the cursor is inside, if any.
---@param buf integer
---@return AnsibleVaultRegion|nil
function M.block_under_cursor(buf)
  if vim.api.nvim_win_get_buf(0) ~= buf then
    return nil
  end

  local cursor_row = vim.api.nvim_win_get_cursor(0)[1]
  local start_row, end_row = yaml.find_block(vim.api.nvim_buf_get_lines(buf, 0, -1, false), cursor_row)
  if not start_row then
    return nil
  end

  local region = M.line_region(buf, start_row, end_row)
  if not region then
    return nil
  end

  region.parsed = yaml.parse_block(table.concat(region.lines, "\n"))
  if not region.parsed then
    return nil
  end

  return region
end

---Whether a newline will follow the last line of a region once it is rewritten.
---
---Only false at the very end of a file that has no final newline, which is
---exactly the case where a value ending in a newline could not otherwise be told
---apart from one that does not.
---@param buf integer
---@param end_row integer 1-based
---@return boolean
local function has_trailing_eol(buf, end_row)
  if end_row < vim.api.nvim_buf_line_count(buf) then
    return true
  end
  return vim.bo[buf].endofline
end

---Work out what a command should act on.
---
---One rule, applied in order:
---
---  1. an explicit `[range]`      -> those lines, as one inline value
---  2. line 1 is a vault header   -> the whole file
---  3. looking for ciphertext     -> the `!vault` block under the cursor
---  4. looking for plaintext      -> the whole buffer
---
---Step 2 comes before step 3 so a whole-file vault never resolves as an inline
---value, and step 4 has no cursor case at all: encrypting one value asks for a
---range, `:.VaultEncrypt` for the current line.
---@param buf integer
---@param opts? table
---@param want "ciphertext"|"plain"
---@return { scope: "file"|"inline", state: "ciphertext"|"plain", region?: AnsibleVaultRegion }|nil
---@return string|nil err
function M.resolve_scope(buf, opts, want)
  if opts and opts.range and opts.range > 0 then
    local region = M.line_region(buf, opts.line1, opts.line2)
    if not region then
      return nil, "the given range is empty"
    end
    region.parsed = yaml.parse_block(table.concat(region.lines, "\n"))
    return { scope = "inline", state = region.parsed and "ciphertext" or "plain", region = region }, nil
  end

  if buffer.is_buffer_encrypted(buf) then
    return { scope = "file", state = "ciphertext" }, nil
  end

  if want == "ciphertext" then
    local region = M.block_under_cursor(buf)
    if region then
      return { scope = "inline", state = "ciphertext", region = region }, nil
    end
    if plaintext.holds_plaintext(buf) then
      return nil, "this buffer already holds decrypted content"
    end
    return nil,
      "nothing encrypted here: this buffer is not an Ansible Vault file, and the cursor "
        .. "is not inside a !vault block. Give a [range] to name one."
  end

  return { scope = "file", state = "plain" }, nil
end

---Whether the value carries on past the end of the selection.
---
---`parse_plaintext` only sees the selected lines, so on its own it reads `vars:`
---with a nested mapping under it as a key with an empty value — and encrypting
---that would turn the parent of those lines into a scalar and orphan them. The
---same applies to a literal block whose body was only half selected. Both are
---silent corruption, so they are refused instead.
---@param buf integer
---@param region AnsibleVaultRegion
---@param continues_at integer|nil Indentation at which the value would continue
---@return string|nil err
function M.continues_below(buf, region, continues_at)
  if not continues_at then
    return nil
  end

  local line_count = vim.api.nvim_buf_line_count(buf)
  for row = region.end_row, line_count - 1 do
    local line = vim.api.nvim_buf_get_lines(buf, row, row + 1, false)[1] or ""
    if line:match("%S") then
      if yaml.indent_width(line) >= continues_at then
        return "the selection stops in the middle of this value; select all of it, "
          .. "or a line that is a value on its own"
      end
      return nil
    end
  end

  return nil
end

---@param buf integer
---@param region AnsibleVaultRegion
---@param lines string[]
---@return boolean ok
---@return any err
local function replace_region(buf, region, lines)
  return pcall(vim.api.nvim_buf_set_lines, buf, region.start_row - 1, region.end_row, false, lines)
end

---Encrypt one selected YAML value in place.
---
---The selection is parsed before `ansible-vault` is invoked, and a selection that
---cannot be read as exactly one scalar is an error rather than a guess: quietly
---encrypting a key, or a neighbouring line, would be indistinguishable from data
---loss once the ciphertext is there.
---@param buf integer
---@param region AnsibleVaultRegion
---@param opts? table
function M.encrypt_region(buf, region, opts)
  local parsed, parse_err = yaml.parse_plaintext(region.lines, has_trailing_eol(buf, region.end_row))
  if not parsed then
    vim.notify("VaultEncrypt: " .. (parse_err or "the selection is not a single YAML value"), vim.log.levels.ERROR)
    return
  end

  local truncated = M.continues_below(buf, region, parsed.continues_at)
  if truncated then
    vim.notify("VaultEncrypt: " .. truncated, vim.log.levels.ERROR)
    return
  end

  local planned_tick = buffer.changedtick(buf)
  local context = buffer.capture_context(buf)

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(buf) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end
    if buffer.changedtick(buf) ~= planned_tick then
      vim.notify("Buffer changed before encryption started; nothing was encrypted", vim.log.levels.ERROR)
      return
    end
    if not buffer.start_operation(buf, "encrypt_string") then
      return
    end

    local args = op.with_encrypt_vault_id(creds.args, opts, creds, context)
    table.insert(args, "--stdin-name")
    table.insert(args, parsed.var_name or "encrypted_string")

    cli.run("encrypt_string", parsed.content, args, function(success, output)
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
        vim.notify("Vault operation finished, but the buffer changed; the result was not applied", vim.log.levels.ERROR)
        return
      end

      local lines, format_err = yaml.format_vault(output, parsed)
      if not lines then
        vim.notify("VaultEncrypt: " .. format_err, vim.log.levels.ERROR)
        return
      end

      -- Encrypting replaces plaintext, so the plaintext becomes undo history.
      -- Hardening first turns off this buffer's 'undofile' for good, which is
      -- what stops the value the user just encrypted reaching an undo file on
      -- their next `:w`. The undo history itself is kept: `:undo` bringing back
      -- the value you just encrypted is the behaviour people expect, and it
      -- never leaves memory.
      if not secure.protect(buf) then
        vim.notify(
          "VaultEncrypt: this buffer could not be secured against swap and undo files; nothing was encrypted",
          vim.log.levels.ERROR
        )
        return
      end

      local ok, err = replace_region(buf, region, lines)
      if not ok then
        vim.notify("Failed to update the selection: " .. tostring(err), vim.log.levels.ERROR)
        return
      end

      vim.notify("Value encrypted successfully", vim.log.levels.INFO)
    end, opts, creds)
  end, opts, context)
end

---Decrypt one inline value in place. `:w` then saves that plaintext.
---@param buf integer
---@param region AnsibleVaultRegion
---@param opts? table
function M.decrypt_region(buf, region, opts)
  local parsed = region.parsed
  local planned_tick = buffer.changedtick(buf)
  local context = buffer.capture_context(buf)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(buf) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end
    if not buffer.start_operation(buf, "decrypt_string") then
      return
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(success, output)
      buffer.finish_operation(buf, "decrypt_string")

      if not success then
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end
      if not buffer.is_valid(buf) then
        vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
        return
      end
      if buffer.changedtick(buf) ~= planned_tick then
        vim.notify("Vault operation finished, but the buffer changed; the result was not applied", vim.log.levels.ERROR)
        return
      end

      local replacement = yaml.format_plaintext(output, parsed, has_trailing_eol(buf, region.end_row))

      -- Hardened before the plaintext is spliced in, so it never reaches the swap
      -- file this buffer would otherwise keep. Clearing the undo history is part
      -- of the same rule: an undone decrypt must not leave the value recoverable
      -- from an undo file.
      local ok, err = secure.set_plaintext_lines(buf, replacement, region.start_row - 1, region.end_row)
      if not ok then
        vim.notify("Failed to update the selection: " .. tostring(err), vim.log.levels.ERROR)
        return
      end

      plaintext.enter(buf)
      vim.notify(string.format("%s decrypted in place", parsed.var_name or "Value"), vim.log.levels.INFO)
    end, opts, creds)
  end, opts, context)
end

---Show one inline value read-only, without changing the buffer.
---@param buf integer
---@param region AnsibleVaultRegion
---@param opts? table
function M.view_region(buf, region, opts)
  local parsed = region.parsed
  local filetype = vim.bo[buf].filetype
  local context = buffer.capture_context(buf)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  op.credentials(function(creds)
    if not creds then
      return
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(success, output)
      if not success then
        vim.notify("View failed: " .. output, vim.log.levels.ERROR)
        return
      end

      local title = parsed.var_name and string.format(" %s (read-only) ", parsed.var_name)
        or " Vault value (read-only) "
      ui.open_float(output, title, filetype)
    end, opts, creds)
  end, opts, context)
end

---Rekey one inline `!vault` value.
---
---`ansible-vault rekey` only takes file paths, so the only way to rotate one
---inline value is decrypt-with-old then encrypt-with-new. The plaintext does
---briefly exist in this process, but only as a local in this function: it is never
---put in a buffer, a buffer variable or a notification, so none of the paths that
---could persist it are involved.
---
---The second stage runs under credentials built for the *new* identity alone.
---Reusing the old ones would let an `ansible.cfg` entry with the same label win
---the lookup and silently re-encrypt with the old password.
---@param buf integer
---@param region AnsibleVaultRegion
---@param opts? table
function M.rekey_region(buf, region, opts)
  local parsed = region.parsed
  -- Keyless list items are a shape this plugin produces, so it has to be able to
  -- rotate them too. The key is not needed to put the value back: the prefix
  -- comes from the buffer, and `--stdin-name` only names the key Ansible echoes
  -- back, which is discarded.
  local value_name = parsed.var_name or "encrypted_string"

  local context = buffer.capture_context(buf)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  local new_creds, new_err = op.new_credentials(opts, context)
  if new_err then
    vim.notify("VaultRekey: " .. new_err, vim.log.levels.ERROR)
    return
  end
  if not new_creds then
    vim.notify("VaultRekey requires new_vault_id, new_password_file, or a --new-vault-* argument", vim.log.levels.ERROR)
    return
  end

  local planned_tick = buffer.changedtick(buf)

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.start_operation(buf, "rekey") then
      return
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(ok, output)
      if not ok then
        buffer.finish_operation(buf, "rekey")
        vim.notify("Rekey failed to decrypt the value: " .. output, vim.log.levels.ERROR)
        return
      end

      -- The decrypted bytes are the value, trailing newline and all. Trimming
      -- here would change what the next decrypt returns.
      local args = vim.deepcopy(new_creds.args)
      vim.list_extend(args, { "--stdin-name", value_name })

      cli.run("encrypt_string", output, args, function(enc_ok, enc_output)
        buffer.finish_operation(buf, "rekey")

        if not enc_ok then
          -- Nothing was replaced, so the block is still there under its old key.
          vim.notify("Rekey failed to re-encrypt the value: " .. enc_output, vim.log.levels.ERROR)
          return
        end
        if not buffer.is_valid(buf) or buffer.changedtick(buf) ~= planned_tick then
          vim.notify("The buffer changed during rekey; the value was left alone", vim.log.levels.ERROR)
          return
        end

        local lines, format_err = yaml.format_vault(enc_output, parsed)
        if not lines then
          vim.notify("VaultRekey: " .. format_err, vim.log.levels.ERROR)
          return
        end

        local replaced, err = replace_region(buf, region, lines)
        if not replaced then
          vim.notify("Failed to update the value: " .. tostring(err), vim.log.levels.ERROR)
          return
        end

        vim.notify(value_name .. " rekeyed successfully", vim.log.levels.INFO)
      end, opts, new_creds)
    end, opts, creds)
  end, opts, context)
end

return M
