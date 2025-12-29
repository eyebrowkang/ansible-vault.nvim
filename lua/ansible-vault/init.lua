---@class AnsibleVaultConfig
---@field password_file? string Path to ansible-vault password file
---@field vault_id? string Vault ID to use for decryption
---@field encrypt_vault_id? string Vault ID to use for encryption (default: "default")
---@field auto_detect? boolean Auto detect vault encrypted files (default: true)
---@field conda_env? string Conda environment name where ansible-vault is installed
---@field ansible_vault_path? string Custom path to ansible-vault executable
---@field debug? boolean Enable debug logging (default: false)

local M = {}

---@type AnsibleVaultConfig
M.config = {
  password_file = nil,
  vault_id = nil,
  encrypt_vault_id = "default",
  auto_detect = true,
  conda_env = nil,
  ansible_vault_path = nil,
  debug = false,
}

---Debug log helper
---@param msg string
---@param ... any
local function debug_log(msg, ...)
  if M.config.debug then
    local formatted = string.format(msg, ...)
    vim.notify("[ansible-vault DEBUG] " .. formatted, vim.log.levels.DEBUG)
    print("[ansible-vault DEBUG] " .. formatted)
  end
end

-- Vault file header pattern
local VAULT_HEADER = "^$ANSIBLE_VAULT;[%d%.]+;AES256"

---Build the ansible-vault command with conda activation if needed
---@return string
local function get_vault_cmd()
  if M.config.ansible_vault_path then
    return M.config.ansible_vault_path
  end

  if M.config.conda_env then
    return string.format(
      'eval "$(conda shell.bash hook)" && conda activate %s && ansible-vault',
      M.config.conda_env
    )
  end

  return "ansible-vault"
end

---Check if content is vault encrypted
---@param content string|string[]
---@return boolean
function M.is_encrypted(content)
  local first_line
  if type(content) == "table" then
    first_line = content[1] or ""
  else
    first_line = content:match("^[^\n]*")
  end
  return first_line:match(VAULT_HEADER) ~= nil
end

---Check if current buffer is vault encrypted
---@return boolean
function M.is_buffer_encrypted()
  local lines = vim.api.nvim_buf_get_lines(0, 0, 1, false)
  return M.is_encrypted(lines)
end

---Get password arguments for ansible-vault
---@param callback fun(args: string[]|nil, cleanup: fun()?): nil
local function get_password_args(callback)
  -- Priority: password_file > vault_id > prompt
  if M.config.password_file then
    callback({ "--vault-password-file", M.config.password_file })
    return
  end

  if M.config.vault_id then
    callback({ "--vault-id", M.config.vault_id })
    return
  end

  -- Prompt for password
  vim.ui.input({ prompt = "Ansible Vault Password: ", default = "" }, function(password)
    if not password or password == "" then
      vim.notify("Password is required", vim.log.levels.ERROR)
      callback(nil)
      return
    end

    -- Create temporary password file
    local tmpfile = os.tmpname()
    local f = io.open(tmpfile, "w")
    if not f then
      vim.notify("Failed to create temp file", vim.log.levels.ERROR)
      callback(nil)
      return
    end
    f:write(password)
    f:close()
    os.execute("chmod 600 " .. tmpfile)

    callback({ "--vault-password-file", tmpfile }, function()
      os.remove(tmpfile)
    end)
  end)
end

---Run ansible-vault command
---@param action string The vault action (encrypt, decrypt, view, encrypt_string)
---@param input string Input content
---@param args string[] Additional arguments
---@param callback fun(success: boolean, output: string): nil
local function run_vault(action, input, args, callback)
  local cmd = get_vault_cmd()
  local full_args = { action }
  vim.list_extend(full_args, args)
  table.insert(full_args, "-")

  -- Build the full command string for shell execution
  local arg_str = table.concat(full_args, " ")
  local shell_cmd = string.format("%s %s", cmd, arg_str)

  local stdout_data = {}
  local stderr_data = {}

  local job_id = vim.fn.jobstart({ "bash", "-c", shell_cmd }, {
    stdin = "pipe",
    stdout_buffered = true,
    stderr_buffered = true,
    on_stdout = function(_, data)
      if data then
        vim.list_extend(stdout_data, data)
      end
    end,
    on_stderr = function(_, data)
      if data then
        vim.list_extend(stderr_data, data)
      end
    end,
    on_exit = function(_, exit_code)
      vim.schedule(function()
        if exit_code == 0 then
          local output = table.concat(stdout_data, "\n")
          -- Remove trailing newline
          output = output:gsub("\n$", "")
          callback(true, output)
        else
          local err = table.concat(stderr_data, "\n")
          callback(false, err)
        end
      end)
    end,
  })

  if job_id <= 0 then
    callback(false, "Failed to start ansible-vault")
    return
  end

  vim.fn.chansend(job_id, input)
  vim.fn.chanclose(job_id, "stdin")
end

---Encrypt current buffer
function M.encrypt()
  if M.is_buffer_encrypted() then
    vim.notify("Buffer is already encrypted", vim.log.levels.WARN)
    return
  end

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    -- Add encrypt-vault-id for encryption
    local encrypt_args = vim.deepcopy(args)
    if M.config.encrypt_vault_id then
      table.insert(encrypt_args, "--encrypt-vault-id")
      table.insert(encrypt_args, M.config.encrypt_vault_id)
    end

    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local content = table.concat(lines, "\n")

    run_vault("encrypt", content, encrypt_args, function(success, output)
      if cleanup then
        cleanup()
      end

      if success then
        local new_lines = vim.split(output, "\n", { plain = true })
        vim.api.nvim_buf_set_lines(0, 0, -1, false, new_lines)
        vim.notify("Buffer encrypted successfully", vim.log.levels.INFO)
      else
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---Decrypt current buffer
function M.decrypt()
  if not M.is_buffer_encrypted() then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local content = table.concat(lines, "\n")

    run_vault("decrypt", content, args, function(success, output)
      if cleanup then
        cleanup()
      end

      if success then
        local new_lines = vim.split(output, "\n", { plain = true })
        vim.api.nvim_buf_set_lines(0, 0, -1, false, new_lines)
        vim.notify("Buffer decrypted successfully", vim.log.levels.INFO)
      else
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---View encrypted buffer in a floating window
function M.view()
  if not M.is_buffer_encrypted() then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local content = table.concat(lines, "\n")

    run_vault("decrypt", content, args, function(success, output)
      if cleanup then
        cleanup()
      end

      if success then
        -- Create floating window
        local buf = vim.api.nvim_create_buf(false, true)
        local new_lines = vim.split(output, "\n", { plain = true })
        vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)

        -- Calculate window size
        local width = math.min(80, vim.o.columns - 4)
        local height = math.min(#new_lines + 2, vim.o.lines - 4)

        local win = vim.api.nvim_open_win(buf, true, {
          relative = "editor",
          width = width,
          height = height,
          col = (vim.o.columns - width) / 2,
          row = (vim.o.lines - height) / 2,
          style = "minimal",
          border = "rounded",
          title = " Vault View (read-only) ",
          title_pos = "center",
        })

        -- Set buffer options
        vim.bo[buf].modifiable = false
        vim.bo[buf].bufhidden = "wipe"
        vim.bo[buf].filetype = vim.bo.filetype

        -- Add keymaps to close
        vim.keymap.set("n", "q", function()
          vim.api.nvim_win_close(win, true)
        end, { buffer = buf, desc = "Close vault view" })

        vim.keymap.set("n", "<Esc>", function()
          vim.api.nvim_win_close(win, true)
        end, { buffer = buf, desc = "Close vault view" })
      else
        vim.notify("View failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---Encrypt selected text (visual mode)
function M.encrypt_string()
  -- Get visual selection
  local start_pos = vim.fn.getpos("'<")
  local end_pos = vim.fn.getpos("'>")
  local lines = vim.fn.getline(start_pos[2], end_pos[2])

  if #lines == 0 then
    vim.notify("No text selected", vim.log.levels.WARN)
    return
  end

  -- Adjust for partial line selection
  if #lines == 1 then
    lines[1] = lines[1]:sub(start_pos[3], end_pos[3])
  else
    lines[1] = lines[1]:sub(start_pos[3])
    lines[#lines] = lines[#lines]:sub(1, end_pos[3])
  end

  local content = table.concat(lines, "\n")

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    -- Add encrypt_string specific args
    local full_args = vim.deepcopy(args)
    if M.config.encrypt_vault_id then
      table.insert(full_args, "--encrypt-vault-id")
      table.insert(full_args, M.config.encrypt_vault_id)
    end
    table.insert(full_args, "--stdin-name")
    table.insert(full_args, "encrypted_string")

    run_vault("encrypt_string", content, full_args, function(success, output)
      if cleanup then
        cleanup()
      end

      if success then
        -- Replace selection with encrypted content
        local new_lines = vim.split(output, "\n", { plain = true })

        vim.api.nvim_buf_set_text(
          0,
          start_pos[2] - 1,
          start_pos[3] - 1,
          end_pos[2] - 1,
          end_pos[3],
          new_lines
        )
        vim.notify("String encrypted successfully", vim.log.levels.INFO)
      else
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---Toggle between encrypted and decrypted state
function M.toggle()
  if M.is_buffer_encrypted() then
    M.decrypt()
  else
    M.encrypt()
  end
end

---Edit encrypted buffer using scratch buffer (no temp file on disk)
function M.edit()
  if not M.is_buffer_encrypted() then
    vim.notify("Buffer is not encrypted", vim.log.levels.WARN)
    return
  end

  local original_buf = vim.api.nvim_get_current_buf()
  local original_file = vim.api.nvim_buf_get_name(original_buf)
  local filetype = vim.bo[original_buf].filetype

  debug_log("VaultEdit: original_file=%s, original_buf=%d", original_file, original_buf)

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    local lines = vim.api.nvim_buf_get_lines(original_buf, 0, -1, false)
    local content = table.concat(lines, "\n")

    run_vault("decrypt", content, args, function(success, output)
      if not success then
        if cleanup then cleanup() end
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      -- Close original buffer first
      vim.api.nvim_buf_delete(original_buf, { force = true })
      debug_log("VaultEdit: closed original buffer %d", original_buf)

      -- Create scratch buffer (no file on disk)
      local edit_buf = vim.api.nvim_create_buf(true, false)
      vim.api.nvim_set_current_buf(edit_buf)

      -- Set buffer content
      local decrypted_lines = vim.split(output, "\n", { plain = true })
      vim.api.nvim_buf_set_lines(edit_buf, 0, -1, false, decrypted_lines)

      -- Set buffer options
      vim.bo[edit_buf].filetype = filetype
      vim.bo[edit_buf].buftype = "acwrite" -- Allow :w but use custom write
      vim.bo[edit_buf].modified = false

      -- Set a virtual name for display (not a real file)
      local display_name = original_file .. " [vault-edit]"
      vim.api.nvim_buf_set_name(edit_buf, display_name)

      debug_log("VaultEdit: created scratch buffer %d, display_name=%s", edit_buf, display_name)

      -- Store metadata
      vim.b[edit_buf].vault_original_file = original_file
      vim.b[edit_buf].vault_password_args = args
      vim.b[edit_buf].vault_cleanup = cleanup

      -- Use BufWriteCmd to intercept :w (no disk write for scratch buffer)
      vim.api.nvim_create_autocmd("BufWriteCmd", {
        buffer = edit_buf,
        callback = function()
          local cur_buf = vim.api.nvim_get_current_buf()
          local edit_lines = vim.api.nvim_buf_get_lines(cur_buf, 0, -1, false)
          local edit_content = table.concat(edit_lines, "\n")
          local orig_file = vim.b[cur_buf].vault_original_file
          local clnup = vim.b[cur_buf].vault_cleanup

          debug_log("VaultEdit: BufWriteCmd triggered, encrypting to %s", orig_file)

          local encrypt_args = vim.deepcopy(vim.b[cur_buf].vault_password_args)
          if M.config.encrypt_vault_id then
            table.insert(encrypt_args, "--encrypt-vault-id")
            table.insert(encrypt_args, M.config.encrypt_vault_id)
          end

          run_vault("encrypt", edit_content, encrypt_args, function(enc_success, enc_output)
            if enc_success then
              -- Write encrypted content to original file
              local orig_f = io.open(orig_file, "w")
              if orig_f then
                orig_f:write(enc_output .. "\n")
                orig_f:close()
                debug_log("VaultEdit: encrypted content written to %s", orig_file)

                if clnup then
                  clnup()
                  vim.b[cur_buf].vault_cleanup = nil
                end

                -- Mark buffer as not modified and close
                vim.bo[cur_buf].modified = false

                vim.schedule(function()
                  vim.api.nvim_buf_delete(cur_buf, { force = true })
                  vim.cmd("edit " .. vim.fn.fnameescape(orig_file))
                  vim.notify("Encrypted and saved: " .. orig_file, vim.log.levels.INFO)
                end)
              else
                vim.notify("Failed to write to original file", vim.log.levels.ERROR)
              end
            else
              vim.notify("Encryption failed: " .. enc_output, vim.log.levels.ERROR)
            end
          end)
        end,
      })

      -- Cleanup on buffer close without save
      vim.api.nvim_create_autocmd("BufDelete", {
        buffer = edit_buf,
        callback = function()
          local clnup = vim.b[edit_buf].vault_cleanup
          if clnup then
            clnup()
          end
          debug_log("VaultEdit: buffer closed")
        end,
      })

      vim.notify("Editing decrypted content (in memory). :w to encrypt and save.", vim.log.levels.INFO)
    end)
  end)
end

---Extract vault content from YAML format, removing indentation
---@param content string
---@return string|nil vault_content
---@return string|nil var_name
local function extract_vault_from_yaml(content)
  debug_log("VaultViewString: raw content:\n%s", content)

  -- Pattern: var_name: !vault |
  --            $ANSIBLE_VAULT;...
  --            encrypted_data...
  local var_name, after_vault = content:match("^%s*([%w_]+):%s*!vault%s*|%s*\n(.+)")
  if not var_name then
    -- Try without variable name: !vault |
    after_vault = content:match("!vault%s*|%s*\n(.+)")
  end

  if after_vault then
    -- Split into lines and remove common indentation
    local vault_lines = vim.split(after_vault, "\n", { plain = true })

    -- Find minimum indentation (only from non-empty lines)
    local min_indent = math.huge
    for _, line in ipairs(vault_lines) do
      if line:match("%S") then
        local indent = #(line:match("^(%s*)") or "")
        min_indent = math.min(min_indent, indent)
      end
    end

    debug_log("VaultViewString: min_indent=%d", min_indent == math.huge and -1 or min_indent)

    -- Remove the common indentation
    if min_indent < math.huge and min_indent > 0 then
      for i, line in ipairs(vault_lines) do
        if #line >= min_indent then
          vault_lines[i] = line:sub(min_indent + 1)
        end
      end
    end

    -- Join and trim
    local result = table.concat(vault_lines, "\n"):gsub("^%s+", ""):gsub("%s+$", "")
    debug_log("VaultViewString: extracted vault content:\n%s", result)
    return result, var_name
  end

  -- Fallback: content starts directly with $ANSIBLE_VAULT
  if content:match("%$ANSIBLE_VAULT") then
    -- Still need to handle indentation
    local lines = vim.split(content, "\n", { plain = true })
    local min_indent = math.huge
    for _, line in ipairs(lines) do
      if line:match("%S") then
        local indent = #(line:match("^(%s*)") or "")
        min_indent = math.min(min_indent, indent)
      end
    end

    if min_indent < math.huge and min_indent > 0 then
      for i, line in ipairs(lines) do
        if #line >= min_indent then
          lines[i] = line:sub(min_indent + 1)
        end
      end
    end

    local result = table.concat(lines, "\n"):gsub("^%s+", ""):gsub("%s+$", "")
    debug_log("VaultViewString: direct vault content:\n%s", result)
    return result, nil
  end

  return nil, nil
end

---View selected encrypted string in floating window (visual mode)
function M.view_string()
  -- Get visual selection
  local start_pos = vim.fn.getpos("'<")
  local end_pos = vim.fn.getpos("'>")
  local lines = vim.fn.getline(start_pos[2], end_pos[2])

  if #lines == 0 then
    vim.notify("No text selected", vim.log.levels.WARN)
    return
  end

  -- For line-wise visual selection, use full lines
  local content = table.concat(lines, "\n")

  debug_log("VaultViewString: selection from line %d to %d", start_pos[2], end_pos[2])

  -- Extract vault content from YAML
  local vault_content, var_name = extract_vault_from_yaml(content)

  if not vault_content or not vault_content:match("%$ANSIBLE_VAULT") then
    vim.notify("Selected text does not appear to be vault encrypted", vim.log.levels.WARN)
    return
  end

  get_password_args(function(args, cleanup)
    if not args then
      return
    end

    run_vault("decrypt", vault_content, args, function(success, output)
      if cleanup then
        cleanup()
      end

      if success then
        -- Create floating window
        local buf = vim.api.nvim_create_buf(false, true)
        local new_lines = vim.split(output, "\n", { plain = true })
        vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)

        -- Calculate window size
        local max_line_len = 0
        for _, line in ipairs(new_lines) do
          max_line_len = math.max(max_line_len, #line)
        end
        local width = math.min(math.max(max_line_len + 2, 40), vim.o.columns - 4)
        local height = math.min(#new_lines + 1, vim.o.lines - 4)

        local title = var_name and string.format(" %s (read-only) ", var_name) or " Vault String (read-only) "

        local win = vim.api.nvim_open_win(buf, true, {
          relative = "editor",
          width = width,
          height = height,
          col = (vim.o.columns - width) / 2,
          row = (vim.o.lines - height) / 2,
          style = "minimal",
          border = "rounded",
          title = title,
          title_pos = "center",
        })

        -- Set buffer options
        vim.bo[buf].modifiable = false
        vim.bo[buf].bufhidden = "wipe"

        -- Add keymaps to close
        vim.keymap.set("n", "q", function()
          vim.api.nvim_win_close(win, true)
        end, { buffer = buf, desc = "Close vault view" })

        vim.keymap.set("n", "<Esc>", function()
          vim.api.nvim_win_close(win, true)
        end, { buffer = buf, desc = "Close vault view" })
      else
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
      end
    end)
  end)
end

---Get status string for statusline
---@return string
function M.status()
  if M.is_buffer_encrypted() then
    return "[VAULT]"
  end
  return ""
end

---Setup the plugin
---@param opts? AnsibleVaultConfig
function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})

  -- Create user commands
  vim.api.nvim_create_user_command("VaultEncrypt", function()
    M.encrypt()
  end, { desc = "Encrypt current buffer with ansible-vault" })

  vim.api.nvim_create_user_command("VaultDecrypt", function()
    M.decrypt()
  end, { desc = "Decrypt current buffer with ansible-vault" })

  vim.api.nvim_create_user_command("VaultView", function()
    M.view()
  end, { desc = "View encrypted buffer in floating window" })

  vim.api.nvim_create_user_command("VaultToggle", function()
    M.toggle()
  end, { desc = "Toggle vault encryption state" })

  vim.api.nvim_create_user_command("VaultEdit", function()
    M.edit()
  end, { desc = "Edit encrypted buffer in temp file" })

  vim.api.nvim_create_user_command("VaultEncryptString", function()
    M.encrypt_string()
  end, { range = true, desc = "Encrypt selected string" })

  vim.api.nvim_create_user_command("VaultViewString", function()
    M.view_string()
  end, { range = true, desc = "View selected encrypted string" })

  -- Auto-detection
  if M.config.auto_detect then
    vim.api.nvim_create_autocmd("BufReadPost", {
      group = vim.api.nvim_create_augroup("AnsibleVault", { clear = true }),
      pattern = "*",
      callback = function()
        if M.is_buffer_encrypted() then
          vim.b.ansible_vault_encrypted = true
        end
      end,
    })
  end
end

return M
