---The three buffers whose writes encrypt: `:VaultCreate`, `:VaultEdit` on a whole
---file, and `:VaultEdit` on one inline value.
---
---All three are the same idea — a protected buffer holding plaintext whose `:w`
---produces ciphertext — so they share one session shape, one write guard and one
---teardown, registered with `plaintext.lua`. What differs is only where the
---ciphertext goes:
---
---  * `create` writes it to a path that did not exist yet;
---  * `file` writes it to the file the scratch was decrypted from;
---  * `inline` writes it back into *one block of the source buffer* and never
---    touches the source YAML file. Saving the file stays the user's decision, so
---    an inline edit cannot smuggle their other unsaved changes onto disk.
---
---Nothing secret is kept in the session. Credentials are resolved when the buffer
---opens and again for every save, so no password, environment or credential
---closure sits in memory for the lifetime of an editing session — and a session
---that outlives its credentials simply asks again.
---
---Every guard is checked twice, before the child process starts and again once it
---returns, because a decrypt or encrypt takes long enough for the user to rename,
---reload, edit or delete either end of the operation in between.
local M = {}

local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local config = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")
local fs = require("ansible-vault.fs")
local op = require("ansible-vault.op")
local plaintext = require("ansible-vault.plaintext")
local secure = require("ansible-vault.secure")
local yaml = require("ansible-vault.yaml")

local notify = config.notify

local SCHEME = "ansible-vault://"

---How long a `:w` may block waiting for `ansible-vault`.
---
---`vim.system` enforces its own timeout and reports it as a failure, so this is
---only a backstop for a child that never reports at all. It has to be longer than
---the CLI's own budget or the backstop would fire first and hide the real error.
---@return integer
local function wait_budget()
  local budget = type(cli.timeout_ms) == "number" and cli.timeout_ms or 0
  if budget <= 0 then
    budget = 30000
  end
  return budget + 5000
end

---@param path string
---@return boolean
local function buffer_exists(path)
  return vim.fn.bufexists(path) == 1
end

--- Delivering the ciphertext ------------------------------------------------

---@param session AnsibleVaultSession
---@param output string
---@param bang boolean
---@return boolean ok
---@return string|nil err
local function publish_file(session, output, bang)
  -- `ansible-vault` exiting 0 is not proof that it produced a vault file; writing
  -- whatever it said over the only copy of the ciphertext would be data loss.
  if not yaml.vault_lines(output) then
    return false, "ansible-vault produced no valid encrypted content; nothing was written"
  end

  local current = fs.signature(session.target)
  if session.kind == "create" and session.signature == nil then
    if current and not bang then
      return false, session.target .. " appeared on disk while you were editing it; use :w! to overwrite it"
    end
  elseif not bang and not fs.same_signature(session.signature, current) then
    return false, session.target .. " changed on disk; the encrypted output was not written"
  end

  local ok, err = fs.atomic_write(session.target, output)
  if not ok then
    return false, "failed to write " .. session.target .. ": " .. tostring(err)
  end

  session.signature = fs.signature(session.target)
  if buffer.is_valid(session.buf) then
    vim.bo[session.buf].modified = false
  end

  -- The buffer this was decrypted from still shows the old ciphertext. Reload it
  -- only when that cannot discard anything: an edit of its own outranks keeping
  -- it in step with the file.
  local source = session.source_buf
  if
    source
    and buffer.is_valid(source)
    and not vim.bo[source].modified
    and vim.api.nvim_buf_get_name(source) == session.target
  then
    pcall(vim.api.nvim_buf_call, source, function()
      vim.cmd("silent! edit!")
    end)
    buffer.remember_header(source)
  end

  notify("Encrypted and saved: " .. session.target, vim.log.levels.INFO)
  return true, nil
end

---Put one re-encrypted value back into the buffer it came from.
---
---Deliberately snapshot-guarded rather than extmark-tracked: if anything about
---the source buffer moved, the block is not replaced at all. Getting the position
---wrong here would overwrite a value the user never opened.
---@param session AnsibleVaultSession
---@param output string
---@param bang boolean
---@return boolean ok
---@return string|nil err
local function publish_inline(session, output, bang)
  local source = session.source_buf

  if not buffer.is_valid(source) then
    return false, "the buffer this value came from no longer exists; nothing was written back"
  end
  if vim.api.nvim_buf_get_name(source) ~= session.source_name then
    return false, "the buffer this value came from was renamed; nothing was written back"
  end
  if buffer.changedtick(source) ~= session.source_tick then
    return false,
      "the buffer this value came from changed while it was open; nothing was written back. "
        .. "Reopen it with :VaultEdit — this buffer's text is not lost"
  end

  local current = vim.api.nvim_buf_get_lines(source, session.start_row - 1, session.end_row, false)
  if not vim.deep_equal(current, session.block_lines) then
    return false,
      "the encrypted block moved or changed; nothing was written back. "
        .. "Reopen it with :VaultEdit — this buffer's text is not lost"
  end

  if
    session.source_file
    and not bang
    and not fs.same_signature(session.source_signature, fs.signature(session.source_file))
  then
    return false, session.source_file .. " changed on disk; use :w! to write the value back anyway"
  end

  local lines, format_err = yaml.format_vault(output, session.parsed)
  if not lines then
    return false, format_err or "ansible-vault returned an invalid encrypted scalar"
  end

  local ok, err = pcall(vim.api.nvim_buf_set_lines, source, session.start_row - 1, session.end_row, false, lines)
  if not ok then
    return false, "failed to update the buffer: " .. tostring(err)
  end

  -- Re-baseline so the value can be saved again without reopening it.
  session.block_lines = lines
  session.end_row = session.start_row + #lines - 1
  session.source_tick = buffer.changedtick(source)
  session.source_signature = session.source_file and fs.signature(session.source_file) or nil

  if buffer.is_valid(session.buf) then
    vim.bo[session.buf].modified = false
  end

  notify(
    string.format("Encrypted %s back into %s; save that buffer to keep it", session.value_name, session.source_label),
    vim.log.levels.INFO
  )
  return true, nil
end

--- The shared write ---------------------------------------------------------

---Encrypt what a session's buffer holds and hand the result to its publisher.
---
---Synchronous from `:w`'s point of view: it drives the asynchronous credential
---resolution and child process to completion and reports the real outcome, so
---`:wq` and `:x` wait for the write instead of quitting on a promise. Every
---callback is gated on the session's epoch, which the write bumps on entry and
---again on exit — a result that arrives after the wait gave up belongs to nobody
---and must not write, clear 'modified' or release a lock.
---@param session AnsibleVaultSession
---@param path string
---@param bang boolean
---@return boolean ok
---@return string|nil err
local function write_session(session, path, bang)
  local buf = session.buf

  if path ~= session.write_name then
    return false,
      string.format(
        "this buffer only writes to %s; :w {file} would write plaintext, so it is refused",
        session.write_name
      )
  end

  if session.kind == "inline" then
    if not buffer.is_valid(session.source_buf) then
      return false, "the buffer this value came from no longer exists; nothing was written back"
    end
    if not buffer.start_operation(session.source_buf, "edit_inline") then
      return false, "another vault operation is running on the buffer this value came from"
    end
  end

  local epoch = session.epoch + 1
  session.epoch = epoch
  local content = buffer.bytes(buf)
  local done, ok, err = false, false, nil

  local function settle(success, message)
    if session.epoch ~= epoch then
      return
    end
    done, ok, err = true, success, message
  end

  local function current()
    return session.epoch == epoch and plaintext.get(buf) == session
  end

  local handle
  op.credentials(function(creds)
    if not current() then
      return
    end
    if not creds then
      settle(false, "no vault credentials were available; nothing was written")
      return
    end

    local args = op.with_encrypt_vault_id(creds.args, session.opts, creds, session.context)
    if session.stdin_name then
      table.insert(args, "--stdin-name")
      table.insert(args, session.stdin_name)
    end

    handle = cli.run(session.action, content, args, function(success, output)
      if not current() then
        return
      end
      if not success then
        settle(false, "encryption failed, nothing was written: " .. output)
        return
      end
      settle(session.publish(session, output, bang))
    end, session.opts, creds)
  end, session.opts, session.context)

  local finished = vim.wait(wait_budget(), function()
    return done
  end, 20)

  -- Past this point nothing from this write may take effect, including a child
  -- that is still running and about to report.
  session.epoch = session.epoch + 1

  if session.kind == "inline" then
    buffer.finish_operation(session.source_buf, "edit_inline")
  end

  if not finished then
    if handle then
      pcall(function()
        handle:kill(15)
      end)
    end
    return false, "timed out waiting for the vault write to finish; nothing was written"
  end

  return ok, err
end

--- Opening a session -------------------------------------------------------

---Put the decrypted bytes into a scratch buffer.
---
---Reports failure rather than leaving an empty buffer behind that looks like an
---empty document: `:w` on one of those would encrypt nothing and replace the
---user's file with it.
---@param buf integer
---@param content string
---@return boolean ok
local function fill_plaintext(buf, content)
  local lines, eol, dos = buffer.content_to_lines(content)
  -- The buffer was hardened when it was created, before this call: swap and undo
  -- files must be off *before* the plaintext exists, not after.
  local ok = secure.with_cleared_undo(buf, function()
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  end)
  if not ok then
    return false
  end

  pcall(function()
    vim.bo[buf].fileformat = dos and "dos" or "unix"
    vim.bo[buf].endofline = eol
    vim.bo[buf].modified = false
  end)
  return true
end

---@param buf integer
---@param preferred_win integer
---@param split boolean
---@return boolean
local function show_buffer(buf, preferred_win, split)
  if not split and vim.api.nvim_win_is_valid(preferred_win) then
    if pcall(vim.api.nvim_win_set_buf, preferred_win, buf) then
      pcall(vim.api.nvim_set_current_win, preferred_win)
      return true
    end
  end

  if not pcall(vim.cmd, "botright split") then
    return false
  end
  return pcall(vim.api.nvim_win_set_buf, 0, buf)
end

---Create a new vault file.
---
---Nothing is created on disk until the first `:w`, and that write is ciphertext.
---A buffer already visiting the path is left alone rather than emptied: the point
---is a new file, not a blank slate over someone's work.
---@param opts table
function M.create(opts)
  local path = opts and opts.positionals and opts.positionals[1]
  if not config.is_nonempty_string(path) then
    vim.notify("VaultCreate requires a file path", vim.log.levels.ERROR)
    return
  end

  path = vim.fn.fnamemodify(credentials.expand_path(path), ":p")

  if vim.uv.fs_stat(path) and not opts.bang then
    vim.notify("File already exists (use :VaultCreate! to overwrite): " .. path, vim.log.levels.ERROR)
    return
  end

  local dir = vim.fn.fnamemodify(path, ":h")
  local dir_stat = vim.uv.fs_stat(dir)
  if not dir_stat or dir_stat.type ~= "directory" then
    vim.notify("Directory does not exist: " .. dir, vim.log.levels.ERROR)
    return
  end

  if buffer_exists(path) then
    vim.notify(path .. " is already open; write or close that buffer first", vim.log.levels.ERROR)
    return
  end

  local buf = secure.create_buffer(true, false)
  local named, name_err = pcall(vim.api.nvim_buf_set_name, buf, path)
  if not named then
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    vim.notify("VaultCreate: " .. tostring(name_err), vim.log.levels.ERROR)
    return
  end

  vim.bo[buf].filetype = vim.filetype.match({ filename = path }) or ""
  vim.bo[buf].modified = false

  local managed = plaintext.manage({
    buf = buf,
    kind = "create",
    action = "encrypt",
    write = write_session,
    publish = publish_file,
    write_name = path,
    target = path,
    signature = fs.signature(path),
    opts = opts,
    context = { file_path = path },
  })

  if not managed then
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    vim.notify("VaultCreate: the new buffer could not be secured; nothing was opened", vim.log.levels.ERROR)
    return
  end

  if not show_buffer(buf, vim.api.nvim_get_current_win(), false) then
    plaintext.release(buf, "never")
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    vim.notify("Failed to open a buffer for " .. path, vim.log.levels.ERROR)
    return
  end

  notify("New vault buffer. :w encrypts and creates " .. path, vim.log.levels.INFO)
end

---Edit a whole encrypted file in a protected scratch buffer.
---@param source integer
---@param opts? table
function M.edit_file(source, opts)
  if vim.bo[source].modified then
    vim.notify("Write or discard changes before VaultEdit", vim.log.levels.ERROR)
    return
  end

  local file = vim.api.nvim_buf_get_name(source)
  if file == "" then
    vim.notify("VaultEdit requires a file-backed buffer", vim.log.levels.ERROR)
    return
  end

  local scratch_name = SCHEME .. file
  if buffer_exists(scratch_name) then
    vim.notify(file .. " is already open in a VaultEdit buffer", vim.log.levels.ERROR)
    return
  end

  local win = vim.api.nvim_get_current_win()
  local filetype = vim.bo[source].filetype
  local tick = buffer.changedtick(source)
  local signature = fs.signature(file)
  local context = buffer.capture_context(source)

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(source) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    cli.run("decrypt", buffer.content(source), creds.args, function(success, output)
      if not success then
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end
      if not buffer.is_valid(source) then
        vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
        return
      end
      if buffer.changedtick(source) ~= tick then
        vim.notify("The buffer changed before VaultEdit opened; the edit was cancelled", vim.log.levels.ERROR)
        return
      end
      if buffer_exists(scratch_name) then
        vim.notify(file .. " is already open in a VaultEdit buffer", vim.log.levels.ERROR)
        return
      end

      -- Hardened before the decrypted lines land, not after.
      local buf = secure.create_buffer(true, false)
      secure.protect(buf)
      local named = pcall(vim.api.nvim_buf_set_name, buf, scratch_name)
      if not named then
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("VaultEdit: buffer name conflict for " .. scratch_name, vim.log.levels.ERROR)
        return
      end

      if not fill_plaintext(buf, output) then
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("VaultEdit: the decrypted content could not be put in a buffer", vim.log.levels.ERROR)
        return
      end
      vim.bo[buf].filetype = filetype

      local managed = plaintext.manage({
        buf = buf,
        kind = "file",
        action = "encrypt",
        write = write_session,
        publish = publish_file,
        write_name = scratch_name,
        target = file,
        signature = signature,
        source_buf = source,
        opts = opts,
        context = context,
      })

      if not managed then
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("VaultEdit: the scratch buffer could not be secured; nothing was opened", vim.log.levels.ERROR)
        return
      end

      if not show_buffer(buf, win, false) then
        plaintext.release(buf, "never")
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("Failed to open the VaultEdit buffer", vim.log.levels.ERROR)
        return
      end

      notify("Editing decrypted content. :w encrypts and saves " .. file, vim.log.levels.INFO)
    end, opts, creds)
  end, opts, context)
end

---Edit one inline `!vault` value in a protected scratch buffer.
---
---The source buffer may already have unsaved changes; they are kept exactly as
---they are. What is not allowed is a change made *after* this opens, because the
---block's position is a snapshot and moving it would put the ciphertext back in
---the wrong place.
---@param source integer
---@param block table From `inline.resolve_scope`
---@param opts? table
function M.edit_inline(source, block, opts)
  local parsed = block.parsed

  -- A list item has no key, and this plugin produces those itself. The key is
  -- not needed to put the value back: `format_vault` builds the whole prefix
  -- from what is in the buffer, and `--stdin-name` only names the key Ansible
  -- echoes back, which is discarded. So a keyless block gets the same fallback
  -- encrypting one does.
  local value_name = parsed.var_name or "encrypted_string"
  local source_name = vim.api.nvim_buf_get_name(source)
  local source_file = source_name ~= "" and source_name or nil
  local source_label = source_file and vim.fn.fnamemodify(source_file, ":t") or "the buffer"
  local scratch_name = string.format(
    "%s%s#%s",
    SCHEME,
    source_name ~= "" and source_name or "buffer",
    parsed.var_name or ("line" .. block.start_row)
  )
  if buffer_exists(scratch_name) then
    vim.notify(value_name .. " is already open in a VaultEdit buffer", vim.log.levels.ERROR)
    return
  end

  local win = vim.api.nvim_get_current_win()
  local tick = buffer.changedtick(source)
  local context = buffer.capture_context(source)
  if parsed.header and parsed.header.label then
    context.header_label = parsed.header.label
  end

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(source) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    cli.run("decrypt", parsed.vault_content, creds.args, function(success, output)
      if not success then
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end
      if not buffer.is_valid(source) or buffer.changedtick(source) ~= tick then
        vim.notify("The buffer changed before VaultEdit opened; the edit was cancelled", vim.log.levels.ERROR)
        return
      end

      local buf = secure.create_buffer(true, false)
      secure.protect(buf)
      local named = pcall(vim.api.nvim_buf_set_name, buf, scratch_name)
      if not named then
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("VaultEdit: buffer name conflict for " .. scratch_name, vim.log.levels.ERROR)
        return
      end

      -- The decrypted bytes are the value, trailing newline and all: 'endofline'
      -- carries whether there was one, so saving reproduces it exactly.
      if not fill_plaintext(buf, output) then
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("VaultEdit: the decrypted value could not be put in a buffer", vim.log.levels.ERROR)
        return
      end

      local managed = plaintext.manage({
        buf = buf,
        kind = "inline",
        action = "encrypt_string",
        stdin_name = value_name,
        write = write_session,
        publish = publish_inline,
        write_name = scratch_name,
        source_buf = source,
        source_name = source_name,
        source_file = source_file,
        source_label = source_label,
        source_signature = source_file and fs.signature(source_file) or nil,
        source_tick = tick,
        start_row = block.start_row,
        end_row = block.end_row,
        block_lines = vim.deepcopy(block.lines),
        parsed = parsed,
        value_name = value_name,
        opts = opts,
        context = context,
      })

      if not managed then
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("VaultEdit: the scratch buffer could not be secured; nothing was opened", vim.log.levels.ERROR)
        return
      end

      if not show_buffer(buf, win, true) then
        plaintext.release(buf, "never")
        pcall(vim.api.nvim_buf_delete, buf, { force = true })
        vim.notify("Failed to open the VaultEdit buffer", vim.log.levels.ERROR)
        return
      end

      notify(
        string.format("Editing %s. :w encrypts it back into %s, which you then save.", value_name, source_label),
        vim.log.levels.INFO
      )
    end, opts, creds)
  end, opts, context)
end

return M
