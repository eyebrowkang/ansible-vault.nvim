---`:VaultEdit` — editing an encrypted file in a scratch buffer.
---
---The alternative to decrypting in place. The original buffer is left holding
---ciphertext and a separate scratch buffer shows the plaintext, so the file on
---disk and the buffer you started from never disagree.
---
---Two things make this more than a convenience wrapper. The scratch buffer is
---hardened from the moment it exists, before any plaintext is put in it. And the
---original file is fingerprinted when the scratch buffer opens and checked again
---before the write lands, so a save cannot silently overwrite someone else's
---changes made while you were editing.
local M = {}

local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local config = require("ansible-vault.config")
local fs = require("ansible-vault.fs")
local op = require("ansible-vault.op")
local secure = require("ansible-vault.secure")

local notify = config.notify

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
  if buffer.is_valid(original_buf) then
    pcall(vim.api.nvim_buf_call, original_buf, function()
      vim.cmd("silent! edit!")
    end)
  end

  if buffer.is_valid(edit_buf) then
    vim.bo[edit_buf].modified = false
  end

  local win = vim.api.nvim_win_is_valid(preferred_win) and preferred_win or vim.api.nvim_get_current_win()
  if buffer.is_valid(original_buf) and vim.api.nvim_win_is_valid(win) then
    vim.api.nvim_win_set_buf(win, original_buf)
  elseif vim.api.nvim_win_is_valid(win) then
    vim.api.nvim_set_current_win(win)
    vim.cmd("edit " .. vim.fn.fnameescape(original_file))
  end

  if buffer.is_valid(edit_buf) then
    vim.api.nvim_buf_delete(edit_buf, { force = true })
  end
end

---Edit encrypted buffer using a scratch buffer.
---@param buf? integer
---@param opts? table
function M.edit(buf, opts)
  local original_buf = buffer.normalize(buf)
  if opts and opts.range and opts.range > 0 then
    vim.notify("VaultEdit works on a whole vault file; use :VaultDecrypt on an inline value", vim.log.levels.ERROR)
    return
  end
  if not buffer.is_valid(original_buf) then
    vim.notify("Target buffer no longer exists", vim.log.levels.ERROR)
    return
  end

  if not buffer.is_buffer_encrypted(original_buf) then
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
  local original_tick = buffer.changedtick(original_buf)
  local original_signature = fs.signature(original_file)

  local context = buffer.capture_context(original_buf)

  op.credentials(function(creds)
    if not creds then
      return
    end

    if not buffer.is_valid(original_buf) then
      buffer.run_cleanup(creds.cleanup)
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    cli.run("decrypt", buffer.content(original_buf), creds.args, function(success, output)
      if not success then
        buffer.run_cleanup(creds.cleanup)
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      if not buffer.is_valid(original_buf) then
        buffer.run_cleanup(creds.cleanup)
        vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
        return
      end

      if buffer.changedtick(original_buf) ~= original_tick then
        buffer.run_cleanup(creds.cleanup)
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
        buffer.run_cleanup(creds.cleanup)
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
          local encrypt_args = op.with_encrypt_vault_id(edit_creds.args, opts, edit_creds, session.context)

          -- 'modified' stays set until the write actually lands. Clearing it up
          -- front would let `:q` wipe the buffer, and its plaintext, while the
          -- encryption is still in flight.
          cli.run("encrypt", edit_content, encrypt_args, function(enc_success, enc_output)
            if not enc_success then
              if buffer.is_valid(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Encryption failed: " .. enc_output, vim.log.levels.ERROR)
              return
            end

            if not fs.same_signature(orig_signature, fs.signature(orig_file)) then
              if buffer.is_valid(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Original file changed on disk; encrypted output was not written", vim.log.levels.ERROR)
              return
            end

            local write_ok, write_err = fs.atomic_write(orig_file, enc_output)
            if not write_ok then
              if buffer.is_valid(cur_buf) then
                vim.b[cur_buf].vault_write_pending = false
              end
              vim.notify("Failed to write encrypted file: " .. write_err, vim.log.levels.ERROR)
              return
            end

            if buffer.is_valid(cur_buf) then
              vim.bo[cur_buf].modified = false
            end

            notify("Encrypted and saved: " .. orig_file, vim.log.levels.INFO)
            op.emit("save", "file", { buf = orig_buf, file = orig_file })
            if buffer.is_valid(cur_buf) then
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
      op.emit("edit", "file", { buf = edit_buf, original_buf = original_buf, file = original_file })
    end, opts, creds)
  end, opts, context)
end

return M
