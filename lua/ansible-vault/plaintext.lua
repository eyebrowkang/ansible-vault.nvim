---Managed buffers: every buffer this plugin lets hold decrypted content.
---
---A managed buffer has 'swapfile' and 'undofile' off and a 'buftype' of
---`acwrite`, which means Neovim runs no write path of its own: no backup file, no
---undo file, and exactly one `BufWriteCmd` deciding what reaches the disk. Three
---different things can be behind that one command, and keeping them apart is the
---point of this module:
---
---  * `:VaultDecrypt` leaves *real plaintext* in the buffer, and `:w` saves that
---    plaintext. Decrypting and then saving is how you decrypt a file; it does not
---    quietly re-encrypt, ask for a password again, or confirm anything.
---  * `:VaultCreate` and `:VaultEdit` put plaintext in a buffer whose writes
---    encrypt. Those writers live in `edit.lua`; they register here so the
---    hardening, the teardown and the "did this write actually land" rules are
---    shared rather than reimplemented per command.
---
---Teardown is ordering-sensitive. Reloading a buffer fires `BufUnload` *while the
---plaintext is still in it* and only then `BufReadPre`/`BufReadPost`, so restoring
---'swapfile' at either of the first two points would write the secret to a swap
---file on the way out. The session is therefore dropped immediately — no further
---write can be hijacked — but the options are put back from a one-shot
---`BufReadPost`, after the new contents have replaced the plaintext. A read that
---fails never reaches that point, and the buffer stays protected.
local M = {}

local buffer = require("ansible-vault.buffer")
local config = require("ansible-vault.config")
local fs = require("ansible-vault.fs")
local secure = require("ansible-vault.secure")

local notify = config.notify

---@class AnsibleVaultSession
---@field buf integer The managed buffer
---@field kind "plaintext"|"create"|"file"|"inline"
---@field write fun(session: AnsibleVaultSession, path: string, bang: boolean): boolean, string|nil
---@field target? string Path this session writes to, for the fixed-target kinds
---@field signature? table Baseline for detecting outside changes to `target`
---@field epoch integer Bumped by every write and by teardown; late callbacks compare it
---@field writing boolean
---@field autocmds integer[]

---@type table<integer, AnsibleVaultSession>
local sessions = {}

---@param buf? integer
---@return AnsibleVaultSession|nil
function M.get(buf)
  if type(buf) ~= "number" then
    return nil
  end
  return sessions[buf]
end

---Whether a buffer is one this plugin manages, and of which kind.
---@param buf? integer
---@return "plaintext"|"create"|"file"|"inline"|nil
function M.kind(buf)
  local session = M.get(buf)
  return session and session.kind or nil
end

---Whether a buffer holds decrypted content that `:w` would save as plaintext.
---@param buf? integer
---@return boolean
function M.holds_plaintext(buf)
  return M.kind(buf) == "plaintext"
end

---Stop managing a buffer.
---
---`restore` says when normal write behaviour may come back:
---  * `"now"`     — the caller has proved no plaintext is left in the buffer;
---  * `"on_read"` — after the buffer's contents have been replaced by a read;
---  * `"never"`   — the buffer is going away.
---@param buf integer
---@param restore? "now"|"on_read"|"never"
function M.release(buf, restore)
  local session = sessions[buf]
  if not session then
    return
  end

  sessions[buf] = nil
  -- Anything still in flight for this session is now stale: it must not write,
  -- clear 'modified', or release a lock a later operation took.
  session.epoch = session.epoch + 1

  for _, id in ipairs(session.autocmds or {}) do
    pcall(vim.api.nvim_del_autocmd, id)
  end
  session.autocmds = {}

  if session.on_release then
    pcall(session.on_release, session)
  end

  if not buffer.is_valid(buf) or restore == "never" then
    return
  end

  if restore == "now" then
    -- No read replaced this text, so persistent undo stays off: the change that
    -- made the buffer ciphertext again could otherwise write the plaintext it
    -- replaced into the undo file. See `secure.restore`.
    secure.restore(buf, false)
  elseif restore ~= nil then
    -- `BufNewFile` as well as `BufReadPost`: re-editing a file that has since
    -- been deleted fires only the former, and the buffer is just as empty either
    -- way. A read that fails outright fires neither, and that buffer keeps its
    -- hardened options deliberately — `:w` then failing with E676 is the correct
    -- end of a write path whose owner is gone.
    pcall(vim.api.nvim_create_autocmd, { "BufReadPost", "BufNewFile" }, {
      buffer = buf,
      once = true,
      desc = "Restore normal write behaviour once the plaintext is gone",
      callback = function()
        -- A read replaces the *contents*, but it is itself one undoable change,
        -- so the plaintext it replaced is still one `:undo` away. Persistent undo
        -- comes back only if the history *actually* went away — a buffer someone
        -- else made 'nomodifiable' cannot be cleared, and then the safe default is
        -- to leave 'undofile' off rather than assume the cleanup happened.
        secure.restore(buf, secure.clear_undo_history(buf))
      end,
    })
  end
end

---Run one write for a session, turning its result into the success or failure the
---`:w` that triggered it needs to see.
---
---A `BufWriteCmd` that only notifies is reported as a *successful* write: `:wq`
---would then quit with the buffer's changes unsaved. Failure therefore leaves
---'modified' set and raises, which is what makes `:wq` and `:x` stay put.
---@param session AnsibleVaultSession
---@param event table
local function run_write(session, event)
  local buf = event.buf

  if sessions[buf] ~= session then
    error("this buffer is no longer managed by ansible-vault.nvim; reopen it with :VaultEdit", 0)
  end

  if session.writing then
    error("a vault write is already running for this buffer", 0)
  end

  local path = event.file
  if not config.is_nonempty_string(path) then
    path = vim.api.nvim_buf_get_name(buf)
  end
  if not config.is_nonempty_string(path) then
    error("cannot write a vault buffer with no file name", 0)
  end

  session.writing = true
  local called, ok, err = pcall(session.write, session, path, vim.v.cmdbang == 1)
  session.writing = false

  if not called then
    error("vault write failed: " .. tostring(ok), 0)
  end
  if not ok then
    error(err or "vault write failed", 0)
  end
end

---Take ownership of a buffer that is about to hold, or already holds, plaintext.
---
---Hardening happens here rather than in the caller's success path, because
---resetting 'swapfile' deletes an existing swap file and must precede the
---plaintext, never follow it.
---
---Returns `nil` if the buffer could not actually be secured, and leaves nothing
---half-installed behind. Every step is checked rather than assumed: a buffer that
---is treated as managed while its writes still go through Neovim's own path is
---the one failure that puts plaintext on disk, so "we asked for it" is not good
---enough — the options are read back to confirm they took.
---@param session AnsibleVaultSession
---@return AnsibleVaultSession|nil
function M.manage(session)
  local buf = session.buf
  M.release(buf, "never")

  secure.protect(buf)
  pcall(function()
    vim.bo[buf].buftype = "acwrite"
  end)

  session.epoch = session.epoch or 0
  session.writing = false
  session.autocmds = {}

  ---@param ok boolean
  ---@param id any
  ---@return boolean
  local function installed(ok, id)
    if ok then
      table.insert(session.autocmds, id)
    end
    return ok
  end

  local secured = installed(pcall(vim.api.nvim_create_autocmd, "BufWriteCmd", {
    buffer = buf,
    desc = "Write an Ansible Vault buffer through the plugin",
    callback = function(event)
      run_write(session, event)
    end,
  }))
    and installed(
      pcall(
        secure.refuse_partial_writes,
        buf,
        "a partial or appending write would put this buffer's plaintext on disk "
          .. "unencrypted, bypassing the vault writer; write the whole buffer instead"
      )
    )
    and installed(pcall(vim.api.nvim_create_autocmd, { "BufUnload", "BufWipeout", "BufReadPre" }, {
      buffer = buf,
      desc = "Drop the Ansible Vault session for a buffer being replaced",
      callback = function()
        -- BufUnload fires while the plaintext is still in the buffer, so the
        -- options stay locked down until a read has replaced it.
        M.release(buf, "on_read")
      end,
    }))
    and vim.bo[buf].buftype == "acwrite"
    and vim.bo[buf].swapfile == false
    and vim.bo[buf].undofile == false

  if not secured then
    for _, id in ipairs(session.autocmds) do
      pcall(vim.api.nvim_del_autocmd, id)
    end
    session.autocmds = {}
    -- Deliberately *not* `secure.restore`: this buffer may already hold
    -- plaintext, and putting 'swapfile' back would write that secret to a swap
    -- file immediately, without the user ever asking for a write. Failing to
    -- secure a buffer is no reason to unsecure it.
    return nil
  end

  sessions[buf] = session

  return session
end

---Whether a write to `path` is this buffer saving itself, as opposed to an
---explicit `:w {other-file}`.
---
---A buffer with no name has nothing for a write to be "other" than, so `:w
---{path}` on one *is* that buffer being saved — which is what Neovim does for an
---ordinary buffer, where 'cpoptions' contains `F` by default. It does not do it
---for an `acwrite` buffer, because the handler owns the write, so the name is
---adopted here instead. Without that, the first `:w {path}` would leave the
---buffer looking unsaved and the second would not.
---@param session AnsibleVaultSession
---@param path string
---@return boolean
local function writes_itself(session, path)
  -- `:saveas` renames the buffer and *then* writes, so a write to the buffer's
  -- current name is this buffer saving itself even when that is not the file it
  -- was decrypted from. Without this the buffer could never be saved again: the
  -- write would be taken for a copy, 'modified' would stay set, and `:wq` would
  -- refuse to quit for the rest of the session.
  local name = vim.api.nvim_buf_get_name(session.buf)
  if name ~= "" then
    return path == name or path == session.target
  end

  -- Unnamed: there is nothing for the write to be "other" than.
  return session.target == nil or path == session.target
end

---Save the plaintext a `:VaultDecrypt`ed buffer is holding.
---
---This is the one writer that puts decrypted bytes on disk, and it does so
---because the user asked for exactly that. It still goes through `atomic_write`
---so a failed write cannot truncate the file it replaces.
---@param session AnsibleVaultSession
---@param path string
---@param bang boolean
---@return boolean ok
---@return string|nil err
local function write_plaintext(session, path, bang)
  local buf = session.buf
  local own = writes_itself(session, path)

  if own and path == session.target then
    if not bang and not fs.same_signature(session.signature, fs.signature(path)) then
      return false, path .. " changed on disk since it was decrypted; use :w! to overwrite it anyway"
    end
  elseif fs.signature(path) and not bang then
    return false, path .. " already exists; use :w! to overwrite it"
  end

  local ok, err = fs.atomic_write(path, buffer.bytes(buf))
  if not ok then
    return false, "failed to write " .. path .. ": " .. tostring(err)
  end

  if own then
    if buffer.is_valid(buf) and vim.api.nvim_buf_get_name(buf) == "" then
      pcall(vim.api.nvim_buf_set_name, buf, path)
    end
    session.target = path
    session.signature = fs.signature(path)
    -- Only the buffer's own file being saved means the buffer is saved. `:w
    -- {other}` copies the text elsewhere and leaves this buffer unsaved.
    if buffer.is_valid(buf) then
      vim.bo[buf].modified = false
    end
  end

  notify("Saved decrypted content: " .. path, vim.log.levels.INFO)
  return true, nil
end

---Manage a buffer that now holds real plaintext, so `:w` saves that plaintext.
---
---The buffer stays managed afterwards: writing it out does not make the remaining
---decrypted content in it any less decrypted.
---@param buf integer
---@return boolean secured
function M.enter(buf)
  if not buffer.is_valid(buf) then
    return false
  end

  -- A buffer whose writes already encrypt keeps that writer. Decrypting one
  -- `!vault` value inside a `:VaultEdit` scratch adds plaintext to plaintext; it
  -- does not turn the scratch into something that saves itself in the clear.
  if M.kind(buf) then
    secure.protect(buf)
    return true
  end

  local name = vim.api.nvim_buf_get_name(buf)
  local session = M.manage({
    buf = buf,
    kind = "plaintext",
    target = name ~= "" and name or nil,
    signature = name ~= "" and fs.signature(name) or nil,
    write = write_plaintext,
  })

  if not session then
    vim.notify(
      "This buffer holds decrypted content but could not be secured; do not write it. "
        .. "Undo the decryption or close it without saving.",
      vim.log.levels.ERROR
    )
    return false
  end

  notify("Buffer holds decrypted content. :w saves it as plaintext.", vim.log.levels.INFO)
  return true
end

---Give a buffer its normal write behaviour back.
---
---Only correct once the caller has established that no plaintext is left in it:
---encrypting one value in a file proves nothing about the rest of it.
---@param buf integer
function M.leave(buf)
  M.release(buf, "now")
end

return M
