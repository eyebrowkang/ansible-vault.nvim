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
---@param buf integer
function M.protect(buf)
  if not is_valid(buf) then
    return
  end

  if vim.b[buf][SAVED_OPTS] == nil then
    vim.b[buf][SAVED_OPTS] = {
      swapfile = vim.bo[buf].swapfile,
      undofile = vim.bo[buf].undofile,
      buftype = vim.bo[buf].buftype,
    }
  end

  -- Resetting 'swapfile' deletes any swap file that already exists.
  vim.bo[buf].swapfile = false
  vim.bo[buf].undofile = false
end

---@param buf integer
---@return boolean
function M.is_protected(buf)
  return is_valid(buf) and vim.b[buf][SAVED_OPTS] ~= nil
end

---Restore the options saved by `protect`. Call once the buffer holds ciphertext
---again, so normal crash recovery comes back.
---@param buf integer
function M.restore(buf)
  if not is_valid(buf) then
    return
  end

  local saved = vim.b[buf][SAVED_OPTS]
  if not saved then
    return
  end

  pcall(function()
    vim.bo[buf].buftype = saved.buftype or ""
    vim.bo[buf].undofile = saved.undofile
    vim.bo[buf].swapfile = saved.swapfile
  end)

  vim.b[buf][SAVED_OPTS] = nil
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

  M.protect(buf)

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
