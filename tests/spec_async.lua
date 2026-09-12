---Everything that can go wrong between a `:w` and the child process reporting.
---
---A `BufWriteCmd` that only notifies is reported to Neovim as a *successful*
---write, so `:wq` would quit with the changes unsaved. Every failure here must
---therefore raise, leave 'modified' set, and leave the target file alone. And a
---result that arrives after its write gave up belongs to nobody: it must not
---write, clear 'modified', or release a lock a later operation took.
---@param H table
---@param tests table
return function(H, tests)
  local eq, yes, no = H.assert_eq, H.assert_true, H.assert_false

  local cli = require("ansible-vault.cli")

  local function slow(seconds, action)
    vim.env.FAKE_VAULT_SLEEP = tostring(seconds)
    if action then
      vim.env.FAKE_VAULT_ACTION = action
    end
  end

  local function whole_edit_fixture(value)
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local source, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope(value or "plain: old\n"))
    return fake, source, path
  end

  local function inline_edit_fixture()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "before: keep" }
    vim.list_extend(input, H.inline("old"))
    table.insert(input, "after: keep")
    local source, path = H.new_file_buffer(fake.dir, "vars.yml", input)
    vim.api.nvim_win_set_cursor(0, { 3, 0 })
    local scratch = H.open_scratch("VaultEdit", source)
    return fake, source, scratch, path, input
  end

  --- :wq and :x wait for the real outcome ---------------------------------

  for _, command in ipairs({ "wq", "x" }) do
    tests[":" .. command .. " waits for a slow vault write to finish"] = function()
      local fake, source, path = whole_edit_fixture()
      vim.cmd("split")
      local windows = #vim.api.nvim_list_wins()
      local scratch = H.open_scratch("VaultEdit", source)
      vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: saved slowly" })

      slow(0.4, "encrypt")
      local before = H.read_file(path)
      vim.cmd("silent " .. command)

      -- No waiting: if the write were reported before the child finished, the
      -- file would still be the old ciphertext at this point.
      no(H.read_file(path) == before, ":" .. command .. " must not return before the write landed")
      yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
      eq(#vim.api.nvim_list_wins(), windows - 1, "the window should be gone once the write succeeded")
      eq(H.calls(fake, "encrypt"), 1)
    end

    tests[":" .. command .. " stays put when the vault write fails"] = function()
      local fake, source, path = whole_edit_fixture()
      vim.cmd("split")
      local windows = #vim.api.nvim_list_wins()
      local scratch = H.open_scratch("VaultEdit", source)
      vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: never saved" })

      vim.env.FAKE_VAULT_ACTION = "encrypt"
      vim.env.FAKE_VAULT_FAIL = "no encryption for you"
      local before = H.read_file(path)
      H.write_fails("silent " .. command)

      eq(H.read_file(path), before, "a failed write must not touch the target")
      yes(vim.bo[scratch].modified, "the user's edit must still be there to retry")
      eq(#vim.api.nvim_list_wins(), windows, ":" .. command .. " must not quit on a failed write")
      eq(vim.api.nvim_get_current_buf(), scratch)
      eq(H.calls(fake, "encrypt"), 1)
    end
  end

  --- Failure, cancellation, timeout --------------------------------------

  tests["a CLI timeout fails the write and keeps the edit"] = function()
    local _, source, path = whole_edit_fixture()
    local scratch = H.open_scratch("VaultEdit", source)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: too slow" })
    local before = H.read_file(path)

    H.patch(cli, "timeout_ms", 200)
    slow(3, "encrypt")
    local message = H.write_fails()

    eq(H.read_file(path), before)
    yes(vim.bo[scratch].modified)
    yes(message:find("timed out", 1, true) or message:find("nothing was written", 1, true), message)

    -- Let the killed child's window pass: nothing may land afterwards.
    vim.wait(1200, function()
      return false
    end, 50)
    eq(H.read_file(path), before, "a result that arrives after the write gave up must not land")
    yes(vim.bo[scratch].modified, "nor may it clear 'modified'")
  end

  tests["no available credentials fails the write instead of writing nothing quietly"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local source, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope("plain: old\n"))
    local scratch = H.open_scratch("VaultEdit", source)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: edited" })
    local before = H.read_file(path)

    -- The credential the buffer opened with is resolved again for every save, so
    -- a save can find itself without one.
    H.reset_config(fake, { password_files = false })
    H.patch(vim.fn, "inputsecret", function()
      return ""
    end)
    H.write_fails()
    eq(H.read_file(path), before)
    yes(vim.bo[scratch].modified)
  end

  for _, output in ipairs({ "invalid", "empty", "truncated" }) do
    tests["an encrypt that exits 0 with " .. output .. " output writes nothing"] = function()
      local _, source, path = whole_edit_fixture()
      local scratch = H.open_scratch("VaultEdit", source)
      vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: edited" })
      local before = H.read_file(path)

      vim.env.FAKE_VAULT_ACTION = "encrypt"
      vim.env.FAKE_VAULT_OUTPUT = output
      local message = H.write_fails()
      eq(H.read_file(path), before, "exit 0 is not proof that ansible-vault produced a vault file")
      yes(vim.bo[scratch].modified)
      yes(message:find("no valid encrypted content", 1, true), message)
      no(message:find("PRIVATE-BAD-OUTPUT", 1, true) ~= nil, "process output must not be quoted back")
      no(H.notification_text():find("PRIVATE-BAD-OUTPUT", 1, true) ~= nil, "process output must not be quoted back")
    end
  end

  tests["a write that cannot reach the filesystem fails and keeps the edit"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir() .. "/locked"
    vim.fn.mkdir(dir, "p")
    local path = dir .. "/new.yml"
    vim.cmd("VaultCreate " .. vim.fn.fnameescape(path))
    local scratch = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "secret: value" })

    vim.fn.setfperm(dir, "r-x------")
    local message = H.write_fails()
    vim.fn.setfperm(dir, "rwx------")

    eq(vim.fn.filereadable(path), 0, "no half-written file may be left behind")
    yes(vim.bo[scratch].modified)
    yes(message:find("failed to write", 1, true), message)
    -- And it still works once the directory does.
    vim.cmd("silent write")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
  end

  --- Results that arrive too late ---------------------------------------

  tests["a buffer destroyed mid-operation is reported, not written to"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_buffer(H.envelope("plain: old\n"))
    slow(0.4, "decrypt")
    vim.cmd("VaultDecrypt")
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    H.wait_until(function()
      return H.notification_contains("no longer exists")
    end, "a vanished buffer should be reported")
    no(vim.api.nvim_buf_is_valid(buf))
  end

  tests["a buffer changed mid-operation does not receive the result"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("old")
    table.insert(input, "other: keep")
    local buf = H.new_buffer(input)
    slow(0.4, "encrypt_string")
    vim.cmd("1,3VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "password: old"
    end)

    slow(0.4, "encrypt_string")
    vim.cmd("1VaultEncrypt")
    -- The user keeps typing while ansible-vault runs, so the recorded line
    -- numbers no longer describe the buffer.
    vim.api.nvim_buf_set_lines(buf, 0, 0, false, { "inserted: line" })
    H.wait_until(function()
      return H.notification_contains("the buffer changed")
    end, "a stale result must be refused")
    eq(H.lines(buf)[1], "inserted: line")
    no(H.text(buf):find("!vault", 1, true) ~= nil, "the result must not be applied at the wrong place")
  end

  --- The source end of an inline edit -----------------------------------

  tests["inline Edit refuses to write back when the source was renamed"] = function()
    local _, source, scratch, path, input = inline_edit_fixture()
    local disk = H.read_file(path)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    vim.api.nvim_buf_set_name(source, path .. ".renamed")
    local message = H.write_fails()
    yes(message:find("renamed", 1, true), message)
    eq(H.lines(source), input, "the block must be left exactly as it was")
    eq(H.read_file(path), disk)
    yes(vim.bo[scratch].modified)
  end

  tests["inline Edit refuses to write back when the source changed after opening"] = function()
    local _, source, scratch, _, input = inline_edit_fixture()
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    -- A snapshot guard rather than extmark tracking: getting the position wrong
    -- would overwrite a value the user never opened.
    vim.api.nvim_buf_set_lines(source, 0, 1, false, { "before: moved", "extra: line" })
    H.write_fails()
    eq(H.lines(source)[3], input[2], "the block must not be spliced at a stale position")
    yes(H.text(source):find("$ANSIBLE_VAULT", 1, true) ~= nil)
    yes(vim.bo[scratch].modified)
  end

  tests["inline Edit refuses to write back when the source is gone"] = function()
    local fake, source, scratch = inline_edit_fixture()
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    pcall(vim.api.nvim_buf_delete, source, { force = true })
    local message = H.write_fails()
    yes(message:find("no longer exists", 1, true), message)
    yes(vim.bo[scratch].modified)
    eq(H.calls(fake, "encrypt_string"), 0, "there is nowhere to put the result, so nothing should run")
  end

  tests["inline Edit refuses to write back while another operation holds the source"] = function()
    local _, source, scratch, _, input = inline_edit_fixture()
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    vim.b[source].ansible_vault_pending = "decrypt"
    local message = H.write_fails()
    yes(message:find("another vault operation", 1, true), message)
    eq(H.lines(source), input)
    vim.b[source].ansible_vault_pending = nil
    -- The lock must have been left as it was found, so a retry works.
    vim.cmd("silent write")
    yes(H.text(source):find("password: !vault |", 1, true) ~= nil)
    eq(vim.b[source].ansible_vault_pending, nil, "the lock must be released after the write")
  end

  tests["a source destroyed while the child runs cannot be written back to"] = function()
    local _, source, scratch, path = inline_edit_fixture()
    local disk = H.read_file(path)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    slow(0.5, "encrypt_string")
    vim.defer_fn(function()
      pcall(vim.api.nvim_buf_delete, source, { force = true })
    end, 100)
    H.write_fails()
    no(vim.api.nvim_buf_is_valid(source))
    eq(H.read_file(path), disk, "the source file must be untouched either way")
    yes(vim.bo[scratch].modified)
  end

  tests["a source edited while the child runs cannot be written back to"] = function()
    local _, source, scratch, path, input = inline_edit_fixture()
    local disk = H.read_file(path)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    slow(0.5, "encrypt_string")
    vim.defer_fn(function()
      vim.api.nvim_buf_set_lines(source, 0, 1, false, { "before: changed mid-write" })
    end, 100)
    H.write_fails()
    eq(H.lines(source)[1], "before: changed mid-write")
    eq(H.lines(source)[2], input[2], "the block must still be the original ciphertext")
    eq(H.read_file(path), disk)
    yes(vim.bo[scratch].modified)
  end

  tests["inline Edit warns when the source file changed on disk and :w! overrides"] = function()
    local _, source, scratch, path = inline_edit_fixture()
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    -- Someone else wrote the file the value came from.
    H.write_file(path, "someone: else\n")
    H.write_fails()
    yes(vim.bo[scratch].modified)
    eq(H.read_file(path), "someone: else\n", "an inline write never saves the source file")
    vim.cmd("silent write!")
    no(vim.bo[scratch].modified)
    yes(H.text(source):find("password: !vault |", 1, true) ~= nil)
    eq(H.read_file(path), "someone: else\n", "not even with a bang")
  end

  --- External change to a fixed target ----------------------------------

  tests["whole Edit refuses a target that changed on disk and :w! overrides"] = function()
    local _, source, path = whole_edit_fixture()
    local scratch = H.open_scratch("VaultEdit", source)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: mine" })
    H.write_file(path, "someone: else\n")
    H.write_fails()
    eq(H.read_file(path), "someone: else\n", "a conflicting write must not be silently overwritten")
    yes(vim.bo[scratch].modified)
    vim.cmd("silent write!")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
    no(vim.bo[scratch].modified)
  end

  tests["a decrypted buffer refuses to overwrite a file that changed under it"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope("plain: old\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "plain: old"
    end)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "plain: mine" })
    H.write_file(path, "someone: else\n")
    H.write_fails()
    eq(H.read_file(path), "someone: else\n")
    yes(vim.bo[buf].modified)
    vim.cmd("silent write!")
    eq(H.read_file(path), "plain: mine\n")
    no(vim.bo[buf].modified)
  end

  --- One session per target ---------------------------------------------

  tests["a second Edit of the same target is refused"] = function()
    local _, source = whole_edit_fixture()
    H.open_scratch("VaultEdit", source)
    vim.api.nvim_set_current_buf(source)
    H.command_fails("VaultEdit")
    yes(H.notification_contains("already open"), H.notification_text())
  end

  tests["Edit refuses a modified source and a buffer with no file"] = function()
    local fake, source = whole_edit_fixture()
    vim.api.nvim_buf_set_lines(source, -1, -1, false, { "dirty" })
    H.command_fails("VaultEdit")
    eq(H.calls(fake, "decrypt"), 0)

    H.new_buffer(H.envelope("plain: old\n"))
    H.command_fails("VaultEdit")
    eq(H.calls(fake, "decrypt"), 0, "there is nowhere to write the ciphertext back to")
  end

  tests["Create refuses a directory that does not exist and a target already open"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    H.command_fails("VaultCreate " .. vim.fn.fnameescape(fake.dir .. "/missing/new.yml"))
    yes(H.notification_contains("Directory does not exist"), H.notification_text())

    local path = fake.dir .. "/open.yml"
    H.open_file(path)
    H.command_fails("VaultCreate " .. vim.fn.fnameescape(path))
    yes(H.notification_contains("already open"), H.notification_text())
    eq(vim.fn.filereadable(path), 0)
  end

  ---The worst outcome this plugin can produce, so it gets its own test.
  ---
  ---If filling the scratch with the decrypted content fails and the failure is
  ---ignored, the scratch is left EMPTY — and its `:w` then encrypts nothing and
  ---writes that over the user's file. The ciphertext is the only copy, so that is
  ---unrecoverable data loss, not an inconvenience. Failing to fill must therefore
  ---destroy the scratch and report, leaving nothing that a later `:w` could
  ---clobber the original with.
  for _, scope in ipairs({ "whole", "inline" }) do
    tests["a scratch that cannot be filled never overwrites the original (" .. scope .. ")"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local dir = H.temp_dir()
      local input = scope == "whole" and H.envelope("plain: original\n") or H.inline("original")
      local _, path = H.new_file_buffer(dir, "vault.yml", input)
      local before = H.read_file(path)
      if scope == "inline" then
        vim.api.nvim_win_set_cursor(0, { 1, 0 })
      end

      -- The scratch is named before it is filled, so this makes the fill fail.
      H.sabotage("BufFilePost", {
        pattern = "ansible-vault://*",
        callback = function(event)
          pcall(function()
            vim.bo[event.buf].modifiable = false
          end)
        end,
      })
      H.command_fails("VaultEdit")

      eq(H.read_file(path), before, "the original ciphertext must be untouched")
      for _, buf in ipairs(vim.api.nvim_list_bufs()) do
        local name = vim.api.nvim_buf_get_name(buf)
        no(name:find("ansible-vault://", 1, true) ~= nil, "an unfilled scratch must not be left open: " .. name)
      end

      -- And whatever is current now, writing it cannot produce an empty vault
      -- file over the original.
      pcall(vim.cmd, "silent write")
      eq(H.read_file(path), before, "no write may replace the original with encrypted emptiness")
    end
  end

  tests["a second write while one is running is refused"] = function()
    local fake, source, path = whole_edit_fixture()
    local scratch = H.open_scratch("VaultEdit", source)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: first" })
    slow(0.4, "encrypt")
    local reentered = nil
    vim.defer_fn(function()
      reentered = pcall(vim.cmd, "silent write")
    end, 100)
    vim.cmd("silent write")
    H.wait_until(function()
      return reentered ~= nil
    end)
    no(reentered, "a re-entrant write must be refused, not run twice")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
    eq(H.calls(fake, "encrypt"), 1, "exactly one child per write")
  end
end
