---The one window this plugin opens.
---
---A read-only float for `:VaultView`. The buffer is created through `secure` and
---marked `bufhidden = "wipe"` because it holds decrypted content: it must not
---persist to disk and must not outlive the window.
---
---`nofile` is not enough to keep it off disk. It stops `:w`, but only because the
---buffer has no file of its own — `:w {path}` from a `nofile` buffer is not
---intercepted at all and writes the decrypted content out with the umask's
---permissions. So the buffer is `acwrite` instead, which routes every write into
---a handler that refuses, exactly as the `:VaultEdit` and `:VaultCreate` buffers
---do. Viewing is a read-only verb; `:VaultDecrypt` is how a user who wants the
---plaintext on disk asks for it.
local M = {}

local cli = require("ansible-vault.cli")
local secure = require("ansible-vault.secure")

---@param output string
---@param title string
---@param filetype? string
function M.open_float(output, title, filetype)
  -- Explicitly hardened rather than relying on the implicit scratch defaults;
  -- this window shows decrypted content.
  local buf = secure.create_buffer(false, true)

  -- Every guard goes on before the decrypted lines do, and each one is read back
  -- rather than assumed: a view whose writes are not refused would put the
  -- decrypted content on disk, which is the one thing this window must not do.
  local REFUSED = "the vault view is read-only; use :VaultDecrypt if you want the decrypted content saved"
  pcall(function()
    vim.bo[buf].buftype = "acwrite"
    vim.bo[buf].bufhidden = "wipe"
  end)
  local guarded = pcall(vim.api.nvim_create_autocmd, "BufWriteCmd", {
    buffer = buf,
    desc = "Refuse to write a read-only vault view",
    callback = function()
      error(REFUSED, 0)
    end,
  }) and pcall(secure.refuse_partial_writes, buf, REFUSED) and vim.bo[buf].buftype == "acwrite"

  if not guarded then
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    vim.notify("VaultView: the view buffer could not be secured; nothing was shown", vim.log.levels.ERROR)
    return
  end

  local lines = cli.output_to_lines(output)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].filetype = filetype or ""
  vim.bo[buf].modifiable = false
  vim.bo[buf].readonly = true

  local max_line_width = 0
  for _, line in ipairs(lines) do
    max_line_width = math.max(max_line_width, vim.api.nvim_strwidth(line))
  end

  local available_width = math.max(1, vim.o.columns - 4)
  local available_height = math.max(1, vim.o.lines - 4)
  local width = math.min(math.max(max_line_width + 2, 40), available_width)
  local height = math.min(math.max(#lines, 1), available_height)

  local win = vim.api.nvim_open_win(buf, true, {
    relative = "editor",
    width = width,
    height = height,
    col = math.max(0, math.floor((vim.o.columns - width) / 2)),
    row = math.max(0, math.floor((vim.o.lines - height) / 2)),
    style = "minimal",
    border = "rounded",
    title = title,
    title_pos = "center",
  })

  local close_window = function()
    if vim.api.nvim_win_is_valid(win) then
      vim.api.nvim_win_close(win, true)
    end
  end

  vim.keymap.set("n", "q", close_window, { buffer = buf, desc = "Close vault view" })
  vim.keymap.set("n", "<Esc>", close_window, { buffer = buf, desc = "Close vault view" })
end

return M
