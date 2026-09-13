---Whole-file Encrypt, Decrypt, View and Rekey implementations.
---Command parsing and scope dispatch live in init.lua; Create/Edit live in edit.lua.
local M = {}

local buffer = require("ansible-vault.buffer")
local cli = require("ansible-vault.cli")
local config = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")
local fs = require("ansible-vault.fs")
local op = require("ansible-vault.op")
local plaintext = require("ansible-vault.plaintext")
local ui = require("ansible-vault.ui")
local yaml = require("ansible-vault.yaml")

---@param target integer
---@param opts table
function M.encrypt(target, opts)
  local kind = plaintext.kind(target)
  if kind and kind ~= "plaintext" then
    vim.notify("This buffer already encrypts what it writes; use :w", vim.log.levels.WARN)
    return
  end

  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(target) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end
    if not buffer.start_operation(target, "encrypt") then
      return
    end

    local tick = buffer.changedtick(target)
    local content = buffer.bytes(target)
    local args = op.with_encrypt_vault_id(creds.args, opts, creds, context)

    cli.run("encrypt", content, args, function(success, output)
      buffer.finish_operation(target, "encrypt")

      if not success then
        vim.notify("Encryption failed: " .. output, vim.log.levels.ERROR)
        return
      end
      if not yaml.vault_lines(output) then
        vim.notify("ansible-vault produced no valid encrypted content; the buffer was left alone", vim.log.levels.ERROR)
        return
      end

      if buffer.replace_lines(target, tick, output, "Buffer encrypted successfully") then
        -- The whole buffer is ciphertext and the undo history that held the
        -- plaintext is gone, so normal write behaviour is safe again. Encrypting
        -- one value out of a file proves no such thing, which is why only this
        -- path releases the buffer.
        plaintext.leave(target)
      end
    end, opts, creds)
  end, opts, context)
end

---@param target integer
---@param opts table
function M.decrypt(target, opts)
  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(target) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end
    if not buffer.start_operation(target, "decrypt") then
      return
    end

    local tick = buffer.changedtick(target)

    cli.run("decrypt", buffer.content(target), creds.args, function(success, output)
      buffer.finish_operation(target, "decrypt")

      if not success then
        vim.notify("Decryption failed: " .. output, vim.log.levels.ERROR)
        return
      end

      -- `replace_lines` hardens the buffer before the plaintext lands in it.
      if buffer.replace_lines(target, tick, output, "Buffer decrypted successfully") then
        plaintext.enter(target)
      end
    end, opts, creds)
  end, opts, context)
end

---@param target integer
---@param opts table
function M.view(target, opts)
  local filetype = vim.bo[target].filetype
  local context = buffer.capture_context(target)

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(target) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end

    cli.run("decrypt", buffer.content(target), creds.args, function(success, output)
      if not success then
        vim.notify("View failed: " .. output, vim.log.levels.ERROR)
        return
      end
      ui.open_float(output, " Vault View (read-only) ", filetype)
    end, opts, creds)
  end, opts, context)
end

---Rekey a whole vault file with the native `rekey`, via a ciphertext staging
---file.
---
---`ansible-vault rekey` rewrites its target in place by removing and recreating
---it, so pointing it at the user's file means a failure part way through leaves
---nothing behind. It is pointed at a copy instead, and the result is published
---over the original in one atomic rename — but only if the original is still
---exactly the file that was copied, and only if what came back is a vault file.
---
---Still the native `rekey`: decrypting and re-encrypting instead would change the
---file's format version and lose its vault id label.
---@param target integer
---@param opts table
function M.rekey(target, opts)
  if vim.bo[target].modified then
    vim.notify("Write or discard changes before VaultRekey", vim.log.levels.ERROR)
    return
  end

  local file = vim.api.nvim_buf_get_name(target)
  if file == "" then
    vim.notify("VaultRekey requires a file-backed buffer", vim.log.levels.ERROR)
    return
  end

  local source, read_err = fs.read_file(file)
  if not source then
    vim.notify("VaultRekey cannot read " .. file .. ": " .. tostring(read_err), vim.log.levels.ERROR)
    return
  end
  if not yaml.vault_lines(source) then
    vim.notify("VaultRekey: " .. file .. " is not an Ansible Vault file on disk", vim.log.levels.ERROR)
    return
  end

  local signature = fs.signature(file)
  local context = buffer.capture_context(target)

  -- Never `--encrypt-vault-id`: on rekey that flag picks from a pool seeded with
  -- the OLD identities, so it can report success having re-encrypted with the old
  -- password. See `credentials.rekey_args`.
  local new_args, new_err = credentials.rekey_args(config.effective(opts), context)
  if new_err then
    vim.notify("VaultRekey: " .. new_err, vim.log.levels.ERROR)
    return
  end
  if not new_args then
    vim.notify("VaultRekey requires new_vault_id, new_password_file, or a --new-vault-* argument", vim.log.levels.ERROR)
    return
  end

  op.credentials(function(creds)
    if not creds then
      return
    end
    if not buffer.is_valid(target) then
      vim.notify("Target buffer no longer exists", vim.log.levels.WARN)
      return
    end
    if not buffer.start_operation(target, "rekey") then
      return
    end

    local staging = vim.fn.tempname()
    local staged, stage_err = fs.atomic_write(staging, source)
    if not staged then
      buffer.finish_operation(target, "rekey")
      vim.notify("VaultRekey could not stage the ciphertext: " .. tostring(stage_err), vim.log.levels.ERROR)
      return
    end

    local args = vim.deepcopy(creds.args)
    vim.list_extend(args, new_args)

    cli.run_file("rekey", staging, args, function(success, output)
      buffer.finish_operation(target, "rekey")

      local produced = fs.read_file(staging)
      fs.remove(staging)

      if not success then
        vim.notify("Rekey failed: " .. output, vim.log.levels.ERROR)
        return
      end
      if not produced or not yaml.vault_lines(produced) then
        vim.notify(
          "Rekey reported success but produced no valid vault content; " .. file .. " was left unchanged",
          vim.log.levels.ERROR
        )
        return
      end
      if not fs.same_signature(signature, fs.signature(file)) then
        vim.notify(file .. " changed on disk during the rekey; it was left unchanged", vim.log.levels.ERROR)
        return
      end
      if buffer.is_valid(target) and vim.bo[target].modified then
        vim.notify(file .. " has unsaved changes again; the rekeyed content was not published", vim.log.levels.ERROR)
        return
      end

      local published, publish_err = fs.atomic_write(file, produced)
      if not published then
        vim.notify("Failed to write the rekeyed file: " .. tostring(publish_err), vim.log.levels.ERROR)
        return
      end

      if buffer.is_valid(target) then
        pcall(vim.api.nvim_buf_call, target, function()
          vim.cmd("silent! edit!")
        end)
        buffer.remember_header(target)
      end

      vim.notify("Vault file rekeyed successfully", vim.log.levels.INFO)
    end, opts, creds)
  end, opts, context)
end

return M
