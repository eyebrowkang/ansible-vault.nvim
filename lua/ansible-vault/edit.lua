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

---@class AnsibleVaultEditSession: AnsibleVaultSession
---@field action "encrypt"|"encrypt_string"
---@field publish fun(session: AnsibleVaultEditSession, output: string, bang: boolean): boolean, string|nil
---@field write_name string Fixed buffer name accepted by the writer
---@field opts? table Per-command options, without resolved credentials
---@field context { file_path?: string, header_label?: string }
---@field stdin_name? string Name echoed by encrypt_string
---@field source_buf? integer Buffer the ciphertext came from
---@field source_name? string Original source buffer name
---@field source_file? string Source path, if file-backed
---@field source_label? string Human-readable source name
---@field source_signature? table Source file conflict baseline
---@field source_tick? integer Source buffer conflict baseline
---@field return_buf? integer Safe buffer to show after a successful write
---@field opened_win? integer Window this session split open for itself
---@field origin_win? integer Window `opened_win` was split from
---@field start_row? integer 1-based, inclusive
---@field end_row? integer 1-based, inclusive
---@field block_lines? string[] Original encrypted block
---@field parsed? table YAML prefix and vault metadata
---@field value_name? string Human-readable inline value name

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

---The whole-file source is where a successful session returns after publishing.
---Checking it before starting a child avoids needless encryption when that return
---is already unsafe; checking it again in `publish_file` closes the race while the
---child was running.
---@param session AnsibleVaultEditSession
---@return boolean ok
---@return string|nil err
local function check_file_source(session)
  if session.kind ~= "file" then
    return true, nil
  end

  local source = session.source_buf
  if not buffer.is_valid(source) then
    return false, "the buffer this file came from no longer exists; nothing was written"
  end
  if vim.api.nvim_buf_get_name(source) ~= session.source_name then
    return false, "the buffer this file came from was renamed; nothing was written"
  end
  if buffer.changedtick(source) ~= session.source_tick or vim.bo[source].modified then
    return false,
      "the buffer this file came from changed while it was open; nothing was written. "
        .. "Reopen it with :VaultEdit — this buffer's text is not lost"
  end

  return true, nil
end

---@param session AnsibleVaultEditSession
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

  local source = session.source_buf
  local source_ok, source_err = check_file_source(session)
  if not source_ok then
    return false, source_err
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

  if session.kind == "file" then
    -- The source was snapshot-guarded above, so it can now be refreshed without
    -- discarding a second set of edits. The write already landed if a hostile
    -- autocmd makes this reload fail; report that honestly and let teardown remove
    -- the plaintext scratch rather than offering a misleading retry.
    session.return_buf = source
    local refreshed = pcall(vim.api.nvim_buf_call, source, function()
      vim.cmd("edit!")
    end)
    if refreshed then
      session.source_tick = buffer.changedtick(source)
      buffer.remember_header(source)
    else
      vim.notify(
        "Encrypted and saved: " .. session.target .. "; the source buffer could not be refreshed",
        vim.log.levels.WARN
      )
    end
  end

  vim.notify("Encrypted and saved: " .. session.target, vim.log.levels.INFO)
  return true, nil
end

---Put one re-encrypted value back into the buffer it came from.
---
---Deliberately snapshot-guarded rather than extmark-tracked: if anything about
---the source buffer moved, the block is not replaced at all. Getting the position
---wrong here would overwrite a value the user never opened.
---@param session AnsibleVaultEditSession
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
  session.return_buf = source

  if buffer.is_valid(session.buf) then
    vim.bo[session.buf].modified = false
  end

  vim.notify(
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
---@param session AnsibleVaultEditSession
---@param path string
---@param bang boolean
---@return boolean ok
---@return string|nil err
local function write_session(session, path, bang)
  local buf = session.buf

  if path ~= session.write_name then
    -- `:saveas` adopts its argument as the buffer name before BufWriteCmd runs.
    -- This session still has one fixed encrypted target, so put the protected
    -- scratch identity back before refusing the redirected write. Otherwise one
    -- failed :saveas would strand the scratch under a name that can never save.
    if buffer.is_valid(buf) and vim.api.nvim_buf_get_name(buf) ~= session.write_name then
      local restored, restore_err = pcall(vim.api.nvim_buf_set_name, buf, session.write_name)
      if not restored then
        return false, "could not restore the protected buffer name: " .. tostring(restore_err)
      end
    end
    return false,
      string.format(
        "this buffer only writes to %s; :w {file} would write plaintext, so it is refused",
        session.write_name
      )
  end

  local source_ok, source_err = check_file_source(session)
  if not source_ok then
    return false, source_err
  end

  if session.kind == "inline" then
    if not buffer.is_valid(session.source_buf) then
      return false, "the buffer this value came from no longer exists; nothing was written back"
    end
    if not buffer.start_operation(session.source_buf, "edit_inline") then
      return false, "another vault operation is running on the buffer this value came from"
    end
  end

  local epoch = plaintext.start_write(session)
  if not epoch then
    if session.kind == "inline" then
      buffer.finish_operation(session.source_buf, "edit_inline")
    end
    return false, "this vault session is no longer active; nothing was written"
  end
  local content = buffer.bytes(buf)
  local content_tick = buffer.changedtick(buf)
  local done, ok, err = false, false, nil

  local function current()
    return plaintext.current(session, epoch)
  end

  local function settle(success, message)
    if not current() then
      return
    end
    done, ok, err = true, success, message
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
      if buffer.changedtick(buf) ~= content_tick then
        settle(false, "the protected buffer changed while it was being encrypted; nothing was written")
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
  plaintext.invalidate(session, epoch)

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
  local ok = secure.set_plaintext_lines(buf, lines)
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

---Put a prepared buffer in front of the user, reporting whether that needed a
---window of its own. A window this plugin opened is one it also closes when the
---session ends, so which it was has to be remembered rather than guessed at from
---the layout later.
---@param buf integer
---@param preferred_win integer
---@param split boolean
---@return boolean shown
---@return integer|nil opened Window this call created, if it had to create one
local function show_buffer(buf, preferred_win, split)
  if not split and vim.api.nvim_win_is_valid(preferred_win) then
    if pcall(vim.api.nvim_win_set_buf, preferred_win, buf) then
      pcall(vim.api.nvim_set_current_win, preferred_win)
      return true, nil
    end
  end

  if not pcall(vim.cmd, "botright split") then
    return false, nil
  end

  local opened = vim.api.nvim_get_current_win()
  if not pcall(vim.api.nvim_win_set_buf, opened, buf) then
    -- Nothing was shown, so nothing may be left of the attempt either.
    pcall(vim.api.nvim_win_close, opened, true)
    return false, nil
  end
  return true, opened
end

---@param buf integer
local function discard_buffer(buf)
  plaintext.release(buf, "never")
  pcall(vim.api.nvim_buf_delete, buf, { force = true })
end

---Create and name a protected buffer without leaving failed attempts behind.
---@param name string
---@return integer|nil buf
---@return any err
local function named_buffer(name)
  local buf = secure.create_buffer(true, false)
  local named, err = pcall(vim.api.nvim_buf_set_name, buf, name)
  if not named then
    discard_buffer(buf)
    return nil, err
  end
  return buf, nil
end

---@param path string
---@return integer|nil buf
---@return string|nil err
local function load_target_buffer(path)
  local existing = vim.fn.bufnr(path)
  if existing > 0 and buffer.is_valid(existing) and vim.bo[existing].modified then
    return nil, path .. " is open with unsaved changes"
  end

  local added, buf = pcall(vim.fn.bufadd, path)
  if not added or type(buf) ~= "number" or buf <= 0 then
    return nil, "could not open " .. path
  end
  if not vim.api.nvim_buf_is_loaded(buf) then
    local loaded, load_err = pcall(vim.fn.bufload, buf)
    if not loaded then
      return nil, "could not read " .. path .. ": " .. tostring(load_err)
    end
  elseif existing > 0 then
    local refreshed, refresh_err = pcall(vim.api.nvim_buf_call, buf, function()
      vim.cmd("edit!")
    end)
    if not refreshed then
      return nil, "could not refresh " .. path .. ": " .. tostring(refresh_err)
    end
  end
  if not buffer.is_valid(buf) then
    return nil, "could not open " .. path
  end

  return buf, nil
end

---@param session AnsibleVaultEditSession
---@return integer|nil buf
---@return string|nil err
local function return_buffer(session)
  if session.return_buf and buffer.is_valid(session.return_buf) then
    return session.return_buf, nil
  end
  if session.kind == "inline" then
    return nil, "the source buffer is no longer available; the protected buffer remains available for recovery"
  end
  return load_target_buffer(session.target)
end

---@param buf integer
---@return integer[] wins
local function windows_showing(buf)
  local wins = {}
  for _, win in ipairs(vim.fn.win_findbuf(buf)) do
    if vim.api.nvim_win_is_valid(win) then
      table.insert(wins, win)
    end
  end
  return wins
end

---Queue the privacy-sensitive teardown only after BufWriteCmd has returned.
---
---`:wq` and `:x` may close their window before scheduled work runs, so cleanup
---must not revive that window or navigate another one. A normal `:w` still has
---its writing window, which is the safe signal to replace the scratch visibly.
---@param session AnsibleVaultEditSession
---@param write_win integer|nil
local function finish_successful_write(session, write_win)
  local scratch = session.buf
  local tick = buffer.changedtick(scratch)
  local epoch = session.epoch
  local original_bufhidden = vim.bo[scratch].bufhidden

  -- A successful :wq/:x must get through its quit phase before the scheduled
  -- cleanup runs. With 'hidden' off, its normal close would unload the scratch
  -- in between, losing the chance to preserve it if (notably for inline Edit)
  -- the only ciphertext destination disappears in that same gap. Hide it just
  -- long enough for the deferred finalizer; all retained recovery buffers put
  -- their original close behaviour back.
  vim.bo[scratch].bufhidden = "hide"

  local function retain_scratch(message)
    if buffer.is_valid(scratch) and plaintext.current(session, epoch) then
      vim.bo[scratch].bufhidden = original_bufhidden
    end
    vim.notify(message, vim.log.levels.WARN)
  end

  vim.schedule(function()
    if not buffer.is_valid(scratch) then
      return
    end

    if not plaintext.current(session, epoch) then
      -- An explicit unload can still beat this callback. An unloaded buffer with
      -- its original URI cannot contain newer edits or have been repurposed, so
      -- wipe it. A loaded or renamed buffer may have been re-read or reused; do
      -- not touch it or a newer session.
      if not vim.api.nvim_buf_is_loaded(scratch) and vim.api.nvim_buf_get_name(scratch) == session.write_name then
        discard_buffer(scratch)
      end
      return
    end

    if buffer.changedtick(scratch) ~= tick or vim.bo[scratch].modified then
      retain_scratch(
        "Vault content was saved, but the protected buffer changed before it could be closed; it remains open"
      )
      return
    end

    local write_win_shows_scratch = write_win
      and vim.api.nvim_win_is_valid(write_win)
      and vim.api.nvim_win_get_buf(write_win) == scratch
    local wins = windows_showing(scratch)

    -- A normal :w leaves at least the writing window visible. :wq/:x normally
    -- leaves none, but another split may still show the same plaintext scratch.
    -- A successful protected save ends that session in every case, so route every
    -- surviving view to the safe destination before wiping it.
    if #wins == 0 then
      -- Inline publishing exists only in the source buffer. If an autocmd
      -- deletes that buffer after publication but before this deferred cleanup,
      -- there is no durable ciphertext destination to recover from. Retain the
      -- hardened scratch rather than turn that narrow race into data loss.
      if session.kind == "inline" then
        local destination, destination_err = return_buffer(session)
        if not destination then
          retain_scratch("Vault content was saved, but " .. tostring(destination_err))
          return
        end
      end
      discard_buffer(scratch)
      return
    end

    local destination, destination_err = return_buffer(session)
    if not destination then
      retain_scratch("Vault content was saved, but " .. tostring(destination_err))
      return
    end

    -- A window this session split open for itself goes away with the session.
    -- Leaving it behind showing the destination is the leftover an inline edit
    -- is most often confused by: a split that now duplicates the window it was
    -- split from. Windows the *user* opened on the same plaintext are theirs, so
    -- those are routed to the destination instead of closed — and so is the
    -- session's own window when it is the last one, because saving a value is no
    -- reason to quit Neovim.
    local closed_own = false
    for _, win in ipairs(wins) do
      if win == session.opened_win and #vim.api.nvim_list_wins() > 1 then
        closed_own = pcall(vim.api.nvim_win_close, win, false) or closed_own
      end
      if vim.api.nvim_win_is_valid(win) then
        pcall(vim.api.nvim_win_set_buf, win, destination)
      end
    end

    -- The window that wrote is where the user is, so it keeps the cursor when it
    -- survives. When it was this session's own window, the window it was split
    -- from is where the user was before, and where the re-encrypted value now is.
    if write_win_shows_scratch and vim.api.nvim_win_is_valid(write_win) then
      pcall(vim.api.nvim_set_current_win, write_win)
    elseif closed_own and session.origin_win and vim.api.nvim_win_is_valid(session.origin_win) then
      pcall(vim.api.nvim_set_current_win, session.origin_win)
    end
    discard_buffer(scratch)
  end)
end

---Register the shared writer before exposing a prepared buffer to the user.
---@param session AnsibleVaultEditSession
---@param win integer
---@param split boolean
---@return boolean opened
---@return "secure"|"show"|nil failure
local function open_session(session, win, split)
  session.write = write_session
  session.on_write_success = finish_successful_write
  if not plaintext.manage(session) then
    discard_buffer(session.buf)
    return false, "secure"
  end
  local shown, opened = show_buffer(session.buf, win, split)
  if not shown then
    discard_buffer(session.buf)
    return false, "show"
  end
  session.opened_win = opened
  session.origin_win = opened and vim.api.nvim_win_is_valid(win) and win or nil
  return true, nil
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

  local scratch_name = SCHEME .. path
  if buffer_exists(scratch_name) then
    vim.notify(path .. " is already open in a VaultCreate buffer", vim.log.levels.ERROR)
    return
  end

  local buf, name_err = named_buffer(scratch_name)
  if not buf then
    vim.notify("VaultCreate: " .. tostring(name_err), vim.log.levels.ERROR)
    return
  end

  vim.bo[buf].filetype = vim.filetype.match({ filename = path }) or ""
  vim.bo[buf].modified = false

  local opened, failure = open_session({
    buf = buf,
    kind = "create",
    action = "encrypt",
    publish = publish_file,
    write_name = scratch_name,
    target = path,
    signature = fs.signature(path),
    opts = opts,
    context = { file_path = path },
  }, vim.api.nvim_get_current_win(), false)

  if not opened then
    if failure == "secure" then
      vim.notify("VaultCreate: the new buffer could not be secured; nothing was opened", vim.log.levels.ERROR)
    else
      vim.notify("Failed to open a buffer for " .. path, vim.log.levels.ERROR)
    end
    return
  end

  vim.notify("New vault buffer. :w encrypts and creates " .. path, vim.log.levels.INFO)
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
      if vim.api.nvim_buf_get_name(source) ~= file then
        vim.notify("The buffer was renamed before VaultEdit opened; the edit was cancelled", vim.log.levels.ERROR)
        return
      end
      if buffer.changedtick(source) ~= tick or vim.bo[source].modified then
        vim.notify("The buffer changed before VaultEdit opened; the edit was cancelled", vim.log.levels.ERROR)
        return
      end
      if buffer_exists(scratch_name) then
        vim.notify(file .. " is already open in a VaultEdit buffer", vim.log.levels.ERROR)
        return
      end

      local buf = named_buffer(scratch_name)
      if not buf then
        vim.notify("VaultEdit: buffer name conflict for " .. scratch_name, vim.log.levels.ERROR)
        return
      end

      -- Hardened before the decrypted lines land, not after: `fill_plaintext`
      -- refuses to write them into a buffer it could not secure.
      if not fill_plaintext(buf, output) then
        discard_buffer(buf)
        vim.notify("VaultEdit: the decrypted content could not be put in a buffer", vim.log.levels.ERROR)
        return
      end
      vim.bo[buf].filetype = filetype

      local opened, failure = open_session({
        buf = buf,
        kind = "file",
        action = "encrypt",
        publish = publish_file,
        write_name = scratch_name,
        target = file,
        signature = signature,
        source_buf = source,
        source_name = file,
        source_tick = tick,
        opts = opts,
        context = context,
      }, win, false)

      if not opened then
        if failure == "secure" then
          vim.notify("VaultEdit: the scratch buffer could not be secured; nothing was opened", vim.log.levels.ERROR)
        else
          vim.notify("Failed to open the VaultEdit buffer", vim.log.levels.ERROR)
        end
        return
      end

      vim.notify("Editing decrypted content. :w encrypts and saves " .. file, vim.log.levels.INFO)
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

      local buf = named_buffer(scratch_name)
      if not buf then
        vim.notify("VaultEdit: buffer name conflict for " .. scratch_name, vim.log.levels.ERROR)
        return
      end

      -- The decrypted bytes are the value, trailing newline and all: 'endofline'
      -- carries whether there was one, so saving reproduces it exactly.
      if not fill_plaintext(buf, output) then
        discard_buffer(buf)
        vim.notify("VaultEdit: the decrypted value could not be put in a buffer", vim.log.levels.ERROR)
        return
      end

      local opened, failure = open_session({
        buf = buf,
        kind = "inline",
        action = "encrypt_string",
        stdin_name = value_name,
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
      }, win, true)

      if not opened then
        if failure == "secure" then
          vim.notify("VaultEdit: the scratch buffer could not be secured; nothing was opened", vim.log.levels.ERROR)
        else
          vim.notify("Failed to open the VaultEdit buffer", vim.log.levels.ERROR)
        end
        return
      end

      vim.notify(
        string.format("Editing %s. :w encrypts it back into %s, which you then save.", value_name, source_label),
        vim.log.levels.INFO
      )
    end, opts, creds)
  end, opts, context)
end

return M
