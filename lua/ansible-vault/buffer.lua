---Buffer identity, the re-entrancy lock, and getting content in and out safely.
---
---Two things here are easy to get wrong and are therefore centralised.
---
---`replace_lines` hardens the buffer *before* plaintext enters it. Resetting
---`'swapfile'` deletes any swap file that already exists, so doing it afterwards
---is too late — see `secure.lua`.
---
---`capture_context` reads the vault header while the buffer still holds
---ciphertext. Once decrypted there is nothing left to recover the vault id label
---from, and re-encrypting without it rewrites the file as format 1.1, silently
---dropping the label. That ordering is a correctness requirement, which is why
---this is named for what it does rather than looking like a plain getter.
local M = {}

local config = require("ansible-vault.config")
local secure = require("ansible-vault.secure")
local yaml = require("ansible-vault.yaml")

---@param buf? integer
---@return integer
function M.normalize(buf)
  return buf or vim.api.nvim_get_current_buf()
end

---@param buf? integer
---@return boolean
function M.is_valid(buf)
  return type(buf) == "number" and vim.api.nvim_buf_is_valid(buf)
end

---@param buf integer
---@return integer
function M.changedtick(buf)
  return vim.b[buf].changedtick or 0
end

---@param buf integer
---@return string
function M.content(buf)
  return table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n")
end

---The bytes a buffer stands for, as this plugin would write them.
---
---'fileformat' and 'endofline' are part of the content, not presentation: a value
---decrypted without a trailing newline has to be written back without one, and a
---file read as `dos` has to keep its CRLFs. Reproducing them here is what makes a
---decrypt/write round trip byte-for-byte.
---@param buf integer
---@return string
function M.bytes(buf)
  local eol = ({ dos = "\r\n", mac = "\r" })[vim.bo[buf].fileformat] or "\n"
  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  return table.concat(lines, eol) .. (vim.bo[buf].endofline and eol or "")
end

---Split raw bytes into buffer lines, reporting how they ended.
---
---`vim.split` on its own turns "a\n" into `{ "a", "" }`, which is a trailing blank
---*line* rather than a trailing newline; writing that back out would grow the
---content by a newline on every round trip. The final newline is returned
---separately so it can live in 'endofline' where it belongs.
---@param content string
---@return string[] lines
---@return boolean eol Whether the content ended with a newline
---@return boolean dos Whether every line ended with CRLF
function M.content_to_lines(content)
  local lines = vim.split(content, "\n", { plain = true })
  local eol = #lines > 1 and lines[#lines] == ""
  if eol then
    table.remove(lines)
  end

  -- Only content that *ends* with a newline can be `dos`. Without one, the final
  -- line has no line ending for its carriage return to live in: stripping it as
  -- part of a CRLF pair and then writing the buffer back with 'noendofline'
  -- would drop that byte silently, turning "a\r" into "a". Left alone it is an
  -- ordinary character, shown as ^M and written back verbatim.
  local dos = eol and #lines > 0
  for _, line in ipairs(lines) do
    if line:sub(-1) ~= "\r" then
      dos = false
      break
    end
  end
  if dos then
    for i, line in ipairs(lines) do
      lines[i] = line:sub(1, -2)
    end
  end

  return lines, eol, dos
end

---@param content string|string[]
---@return string
local function first_line_of(content)
  if type(content) == "table" then
    return content[1] or ""
  end
  return content:match("^[^\n]*") or ""
end

---Parse the `$ANSIBLE_VAULT` header of some content.
---@param content string|string[]
---@return AnsibleVaultHeader|nil
function M.parse_header(content)
  return yaml.parse_header(first_line_of(content))
end

---@param content string|string[]
---@return boolean
function M.is_encrypted(content)
  return M.parse_header(content) ~= nil
end

---@param buf? integer
---@return boolean
function M.is_buffer_encrypted(buf)
  local target = M.normalize(buf)
  if not M.is_valid(target) then
    return false
  end
  return M.is_encrypted(vim.api.nvim_buf_get_lines(target, 0, 1, false))
end

---Record the vault format version and id label a buffer's ciphertext carries, so
---re-encrypting can preserve them instead of silently downgrading to format 1.1.
---@param buf integer
---@param content? string|string[]
function M.remember_header(buf, content)
  if not M.is_valid(buf) then
    return
  end

  local header = M.parse_header(content or vim.api.nvim_buf_get_lines(buf, 0, 1, false))

  -- Deliberately no else branch. This runs again once the buffer holds plaintext,
  -- and that content has no header to read a label from; keeping the last one
  -- seen is exactly what lets `:VaultDecrypt` + `:VaultEncrypt` put the 1.2 label
  -- back instead of silently rewriting the file as 1.1.
  if header then
    vim.b[buf].ansible_vault_version = header.version
    vim.b[buf].ansible_vault_label = header.label
  end
end

---Describe which file an operation applies to, so credentials and the encryption
---label resolve the way Ansible would resolve them there.
---
---Records the header as a side effect, and must therefore be called before the
---buffer is decrypted.
---@param buf? integer
---@return { file_path?: string, header_label?: string }
function M.capture_context(buf)
  local context = {}
  if buf and vim.api.nvim_buf_is_valid(buf) then
    M.remember_header(buf)

    local name = vim.api.nvim_buf_get_name(buf)
    if name ~= "" then
      context.file_path = name
    end
    context.header_label = vim.b[buf].ansible_vault_label
  end
  if not context.file_path then
    context.file_path = vim.api.nvim_buf_get_name(vim.api.nvim_get_current_buf())
    if context.file_path == "" then
      context.file_path = nil
    end
  end
  return context
end

---Claim a buffer for one operation at a time.
---@param buf integer
---@param operation string
---@return boolean
function M.start_operation(buf, operation)
  if vim.b[buf].ansible_vault_pending then
    vim.notify(
      string.format("Vault operation already running: %s", vim.b[buf].ansible_vault_pending),
      vim.log.levels.WARN
    )
    return false
  end

  vim.b[buf].ansible_vault_pending = operation
  return true
end

---@param buf integer
---@param operation string
function M.finish_operation(buf, operation)
  if M.is_valid(buf) and vim.b[buf].ansible_vault_pending == operation then
    vim.b[buf].ansible_vault_pending = nil
  end
end

---Put `ansible-vault` output into a buffer, hardening first when it is plaintext.
---
---The buffer's 'fileformat' and 'endofline' are set from the output rather than
---left over from whatever the file used to be, because they are the only place a
---final newline can be recorded. A vault file stored with CRLFs would otherwise
---put a carriage return back on every line of the plaintext written out of it.
---@param buf integer
---@param expected_changedtick integer
---@param output string
---@param success_message string
---@return boolean
function M.replace_lines(buf, expected_changedtick, output, success_message)
  if not M.is_valid(buf) then
    vim.notify("Vault operation finished, but the target buffer no longer exists", vim.log.levels.WARN)
    return false
  end

  if M.changedtick(buf) ~= expected_changedtick then
    vim.notify("Vault operation finished, but the buffer changed; result was not applied", vim.log.levels.ERROR)
    return false
  end

  local lines, eol, dos = M.content_to_lines(output)
  local becomes_plaintext = not M.is_encrypted(lines)

  local ok, err
  if becomes_plaintext then
    -- Harden first: resetting 'swapfile' deletes any existing swap file, and
    -- doing it before the plaintext lands is what keeps it off disk.
    ok, err = secure.set_plaintext_lines(buf, lines)
  else
    -- A change made while 'undolevels' is -1 discards the undo tree, so the
    -- plaintext this content replaces is not left sitting in undo history that a
    -- later 'undofile' write could persist.
    ok, err = secure.with_cleared_undo(buf, function()
      vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    end)
  end

  if not ok then
    vim.notify("Failed to update buffer: " .. tostring(err), vim.log.levels.ERROR)
    return false
  end

  pcall(function()
    vim.bo[buf].fileformat = dos and "dos" or "unix"
    vim.bo[buf].endofline = eol
  end)

  M.remember_header(buf, lines)
  config.notify(success_message, vim.log.levels.INFO)
  return true
end

return M
