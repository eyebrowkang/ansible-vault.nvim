---Plaintext protection helpers.
---
---Neovim persists buffer contents to disk in several ways that outlive a crash:
---the swap file, the persistent undo file, and 'backup'/'writebackup'. Decrypted
---vault content must never reach any of them.
---
---Ordering matters. Resetting 'swapfile' deletes the buffer's existing swap file
---immediately, so it has to happen *before* plaintext enters the buffer, never
---after. Routing writes through a 'buftype' of "acwrite" takes care of the rest:
---Neovim skips its own write path entirely, so no backup file is made and no
---undo file is written.
---
---Coming back out is not symmetrical with going in, which is why `restore` takes
---an argument: an undo file can still be written *after* the buffer is ciphertext
---again, carrying the plaintext that change replaced. See `restore`.
local M = {}

local SAVED_OPTS = "ansible_vault_saved_opts"

---@param buf integer
---@return boolean
local function is_valid(buf)
  return type(buf) == "number" and vim.api.nvim_buf_is_valid(buf)
end

---Disable every buffer-local option that can persist buffer contents to disk.
---
---Must be called before decrypted content is written into the buffer. Safe to
---call repeatedly; the first call is the one that records the original values.
---
---Reports whether the buffer is *now* protected, by reading the options back
---rather than by assuming the assignments took. Every caller has to treat `false`
---as "do not put plaintext in this buffer": it is the one question whose wrong
---answer puts a secret in a swap or undo file.
---@param buf integer
---@return boolean protected
function M.protect(buf)
  if not is_valid(buf) then
    return false
  end

  if vim.b[buf][SAVED_OPTS] == nil then
    vim.b[buf][SAVED_OPTS] = {
      swapfile = vim.bo[buf].swapfile,
      undofile = vim.bo[buf].undofile,
      buftype = vim.bo[buf].buftype,
    }
  end

  -- Resetting 'swapfile' deletes any swap file that already exists.
  pcall(function()
    vim.bo[buf].swapfile = false
    vim.bo[buf].undofile = false
  end)

  return vim.bo[buf].swapfile == false and vim.bo[buf].undofile == false
end

---Restore the options saved by `protect`. Call once the buffer holds ciphertext
---again, so normal crash recovery comes back.
---
---'undofile' is the exception, and deliberately so. Clearing the undo tree stops
---the plaintext being *reachable* in this session, but it does not stop Neovim
---writing the text a change replaced into the undo file on the next ordinary
---write. Decrypting and re-encrypting in place therefore leaves a buffer whose
---next `:w` would persist the plaintext it just encrypted away, even though the
---file on disk only ever held ciphertext.
---
---So persistent undo only comes back when `text_reloaded` says the buffer's
---contents were replaced by a *read* **and** the caller has already thrown the
---undo history away with `clear_undo_history` — a read on its own is not enough,
---because the reload is itself one undoable change holding the plaintext it
---replaced. Otherwise 'undofile' stays off for the rest of that buffer's life.
---The cost is no cross-session undo for a buffer that held a secret; undo within
---the session is unaffected, because 'undolevels' is restored either way.
---
---'swapfile' needs no such rule: it is rebuilt from the buffer's current
---contents, which are ciphertext by the time this runs.
---@param buf integer
---@param text_reloaded? boolean Whether a read has replaced the buffer's contents
function M.restore(buf, text_reloaded)
  if not is_valid(buf) then
    return
  end

  local saved = vim.b[buf][SAVED_OPTS]
  if not saved then
    return
  end

  pcall(function()
    vim.bo[buf].buftype = saved.buftype or ""
    vim.bo[buf].swapfile = saved.swapfile
    if text_reloaded then
      vim.bo[buf].undofile = saved.undofile
    end
  end)

  vim.b[buf][SAVED_OPTS] = nil
end

---Refuse the writes that would otherwise go around this plugin's writer.
---
---`acwrite` sends `:w`, `:w {file}` and `:saveas` through the buffer's
---`BufWriteCmd`, but it does *not* cover a partial-range write or an append:
---`:1w {file}` raises `FileWriteCmd` and `:w >> {file}` raises `FileAppendCmd`,
---and with no handler Neovim writes those lines out itself — unencrypted, without
---the atomic write, and with the umask's permissions rather than 0600.
---
---Registered per buffer, so nobody else's `:w` is affected.
---@param buf integer
---@param message string
---@return integer autocmd id
function M.refuse_partial_writes(buf, message)
  return vim.api.nvim_create_autocmd({ "FileWriteCmd", "FileAppendCmd" }, {
    buffer = buf,
    desc = "Refuse writes that would bypass the Ansible Vault writer",
    callback = function()
      error(message, 0)
    end,
  })
end

---Run `fn` with undo disabled, so the change it makes leaves no recoverable
---state behind. Restoring the saved 'undolevels' re-enables undo for subsequent
---edits; the value may be -123456, meaning "use the global value".
---@param buf integer
---@param fn fun()
---@return boolean ok
---@return any result_or_error
function M.with_cleared_undo(buf, fn)
  if not is_valid(buf) then
    return pcall(fn)
  end

  local saved = vim.bo[buf].undolevels
  vim.bo[buf].undolevels = -1

  local ok, result = pcall(fn)

  pcall(function()
    vim.bo[buf].undolevels = saved
  end)

  return ok, result
end

---Discard a buffer's entire undo history, in place.
---
---`with_cleared_undo` stops a *change* being recorded; this throws away what is
---already there. Needed because reloading a buffer is itself one undoable change,
---so a buffer that was decrypted and then re-read still has the plaintext sitting
---one `:undo` away — and one ordinary write away from an undo file.
---
---The documented recipe (`:h clear-undo`): with 'undolevels' at -1, make one
---change, which discards the tree instead of adding to it. The change is a space
---typed and immediately erased, so the text is identical afterwards; 'modified'
---is put back because that no-op must not make a freshly read buffer look edited.
---
---Reports whether the history is *actually* gone, by looking at the resulting
---undo tree rather than at whether the attempt appeared to run. A buffer someone
---else made 'nomodifiable' cannot be cleared at all, and `silent!` deliberately
---swallows the error the `normal!` would otherwise raise — so "it executed" is no
---evidence. Callers must treat `false` as "the plaintext is still reachable".
---@param buf integer
---@return boolean cleared
function M.clear_undo_history(buf)
  if not is_valid(buf) or not vim.bo[buf].modifiable then
    return false
  end

  local modified = vim.bo[buf].modified
  local undolevels = vim.bo[buf].undolevels

  vim.bo[buf].undolevels = -1
  local ok, cleared = pcall(vim.api.nvim_buf_call, buf, function()
    vim.cmd("silent! noautocmd normal! a \8\27")
    return #vim.fn.undotree().entries == 0
  end)

  pcall(function()
    vim.bo[buf].undolevels = undolevels
    vim.bo[buf].modified = modified
  end)

  return ok and cleared == true
end

---Replace a buffer's contents with plaintext, hardening it first and leaving no
---undo history that could reach an undo file.
---@param buf integer
---@param lines string[]
---@return boolean ok
---@return any err
function M.set_plaintext_lines(buf, lines)
  if not is_valid(buf) then
    return false, "buffer no longer exists"
  end

  -- Checked before the plaintext goes in, not after. A buffer that could not be
  -- hardened keeps its ciphertext: putting the secret in first and discovering
  -- the problem afterwards means it is already in a swap file.
  if not M.protect(buf) then
    return false, "the buffer could not be secured against swap and undo files"
  end

  return M.with_cleared_undo(buf, function()
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  end)
end

---Create a buffer that is safe to hold plaintext from the moment it exists.
---@param listed boolean
---@param scratch boolean
---@return integer
function M.create_buffer(listed, scratch)
  local buf = vim.api.nvim_create_buf(listed, scratch)
  vim.bo[buf].swapfile = false
  vim.bo[buf].undofile = false
  return buf
end

---Global options the plugin deliberately does not change, but which can still
---leak plaintext the user put somewhere we do not control.
---@return string[]
function M.global_warnings()
  local warnings = {}

  if vim.o.shada ~= "" then
    table.insert(
      warnings,
      "'shada' is enabled: text yanked out of a decrypted buffer is written to the shada file on exit"
    )
  end

  if vim.o.backup then
    table.insert(warnings, "'backup' is enabled: writes outside this plugin keep a plaintext copy alongside the file")
  end

  if vim.o.writebackup and vim.o.backupcopy:match("yes") then
    table.insert(warnings, "'writebackup' with 'backupcopy=yes' writes a plaintext copy during unmanaged writes")
  end

  return warnings
end

return M
