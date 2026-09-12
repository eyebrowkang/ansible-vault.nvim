---Plaintext mode: the single point where decrypted content can reach the disk.
---
---Once a buffer holds plaintext, `'buftype'` is `acwrite` and one `BufWriteCmd`
---owns every write. That is what makes `:w`, `:wq`, `:x` and even
---`:w {other-file}` all encrypt first, and what stops Neovim from writing a backup
---or an undo file along the way. There is deliberately no second path out.
---
---Two shapes exist. "file" means the whole buffer is plaintext, so a write
---encrypts all of it. "inline" means the buffer is ordinary YAML with some
---`!vault` values decrypted in place: each is tracked by an extmark, a write folds
---exactly those back into `!vault` blocks, and the surrounding lines are written
---unchanged. The second is what makes a partly-encrypted file work at all.
---
---The extmark is left-gravity, so deleting a decrypted value collapses its region
---onto the following line. The fold-back therefore checks the key recorded at
---decrypt time still matches before replacing anything; otherwise it would
---encrypt a value the user never decrypted.
local M = {}

local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local config = require("ansible-vault.config")
local fs = require("ansible-vault.fs")
local op = require("ansible-vault.op")
local secure = require("ansible-vault.secure")
local yaml = require("ansible-vault.yaml")

local notify = config.notify
local is_nonempty_string = config.is_nonempty_string
local NAMESPACE = vim.api.nvim_create_namespace("ansible-vault")

local write_plaintext_buffer

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
function M.mode(buf)
  if not buffer.is_valid(buf) then
    return nil
  end
  return vim.b[buf].ansible_vault_plaintext
end

---@param buf integer
---@param mode "file"|"inline"
---@param opts? table
function M.enter(buf, mode, opts)
  if not buffer.is_valid(buf) then
    return
  end

  secure.protect(buf)

  if M.mode(buf) then
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
    vim.log.levels.INFO
  )
end

---Return the buffer to its normal, ciphertext-backed behaviour.
---@param buf integer
function M.leave(buf)
  if not buffer.is_valid(buf) then
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

--- Inline region tracking -------------------------------------------------
---
---After decrypting one inline value, the buffer holds that plaintext inside an
---otherwise ordinary YAML file. An extmark follows that region through
---subsequent edits so `:w` can fold exactly it back into a `!vault` block.

---@param buf integer
---@param start_row integer 0-based
---@param end_row integer 0-based
---@param parsed table
function M.track_region(buf, start_row, end_row, parsed)
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
function M.restore_regions(buf, opts, callback)
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

  local context = buffer.capture_context(buf)

  op.credentials(function(creds)
    if not creds then
      callback(false)
      return
    end

    local index = 0
    local function step()
      index = index + 1
      if index > #resolved then
        buffer.run_cleanup(creds.cleanup)
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

      local args = op.with_encrypt_vault_id(
        creds.args,
        opts,
        creds,
        vim.tbl_extend("force", context, { header_label = region.label or context.header_label })
      )
      table.insert(args, "--stdin-name")
      table.insert(args, name or "encrypted_string")

      cli.run("encrypt_string", content, args, function(success, output)
        if not success then
          buffer.run_cleanup(creds.cleanup)
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
          buffer.run_cleanup(creds.cleanup)
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
  if not buffer.is_valid(buf) then
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
    if buffer.is_valid(buf) then
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
    M.restore_regions(buf, opts, function(ok)
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

      M.leave(buf)
      notify("Vault values restored and saved: " .. path, vim.log.levels.INFO)
      op.emit("save", "inline", { buf = buf, file = path })
      finish(true)
    end)
    await()
    return
  end

  local context = buffer.capture_context(buf)
  local content = buffer.content(buf)

  op.credentials(function(creds)
    if not creds then
      finish(false)
      return
    end

    local args = op.with_encrypt_vault_id(creds.args, opts, creds, context)

    cli.run("encrypt", content, args, function(success, output)
      buffer.run_cleanup(creds.cleanup)

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
      op.emit("save", "file", { buf = buf, file = path })
      finish(true)
    end, opts, creds)
  end, opts, context)

  await()
end

return M
