---What must never happen to decrypted content or to a password.
---
---The rule these tests encode: the plugin prevents *unintended* copies. It does
---not try to defeat a user who ran `:VaultDecrypt` and then saved the file, which
---is what that command is for. So "leak" here means a swap file, an undo file, a
---backup, a temporary file, an undo history, a log line or a notification — never
---the file the user asked for.
---@param H table
---@param tests table
return function(H, tests)
  local eq, yes, no = H.assert_eq, H.assert_true, H.assert_false

  local SECRET = "CANARY-PLAINTEXT-3f91"

  ---Give this test its own swap, undo and backup directories, with swap files
  ---actually enabled: headless Neovim sets 'updatecount' to 0, and every test
  ---here would otherwise pass because Neovim never wrote a swap file at all.
  local function persistence_dirs()
    local base = H.temp_dir()
    local dirs = { swap = base .. "/swap", undo = base .. "/undo", backup = base .. "/backup" }
    for _, dir in pairs(dirs) do
      vim.fn.mkdir(dir, "p")
    end
    vim.o.updatecount = 200
    vim.o.directory = dirs.swap .. "//"
    vim.o.undodir = dirs.undo
    vim.o.backupdir = dirs.backup
    vim.o.undofile = true
    vim.o.swapfile = true
    dirs.base = base
    return dirs
  end

  local function assert_no_persisted_copy(dirs, needle)
    for _, key in ipairs({ "swap", "undo", "backup" }) do
      eq(H.grep_under(dirs[key], needle or SECRET), {}, key .. " directory must hold no decrypted content")
    end
  end

  ---True only if the buffer was already hardened at the moment its lines changed.
  ---Resetting 'swapfile' deletes an existing swap file, so doing it after the
  ---plaintext arrives is too late, and no after-the-fact option check can tell
  ---the two orders apart.
  local function watch_hardening(buf)
    local state = { checked = false, hardened = nil }
    vim.api.nvim_buf_attach(buf, false, {
      on_lines = function()
        if not state.checked then
          state.checked = true
          state.hardened = vim.bo[buf].swapfile == false
            and vim.bo[buf].undofile == false
            and vim.fn.swapname(buf) == ""
        end
      end,
    })
    return state
  end

  --- Hardening ordering ----------------------------------------------------

  for _, scope in ipairs({ "whole", "inline" }) do
    tests[scope .. " Decrypt hardens the buffer before the plaintext arrives"] = function()
      local dirs = persistence_dirs()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local input = scope == "whole" and H.envelope("api_key: " .. SECRET .. "\n") or H.inline(SECRET, "api_key:")
      local buf, path = H.new_file_buffer(dirs.base, "vault.yml", input)
      yes(vim.bo[buf].swapfile, "precondition: the ciphertext buffer starts with swap enabled")
      yes(vim.fn.swapname(buf) ~= "", "precondition: a swap file exists before decrypting")
      local swap_before = vim.fn.swapname(buf)

      local watch = watch_hardening(buf)
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return H.text(buf):find(SECRET, 1, true) ~= nil
      end)

      yes(watch.checked, "the decrypt should have changed the buffer")
      yes(watch.hardened, "'swapfile'/'undofile' must be off before decrypted lines land")
      eq(vim.fn.filereadable(swap_before), 0, "the pre-existing swap file must be deleted")
      H.assert_hardened(buf)

      -- Force every persistence path Neovim has.
      vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "extra: line" })
      vim.cmd("silent! preserve")
      vim.cmd("silent write")
      assert_no_persisted_copy(dirs)
      eq(H.read_file(path):find(SECRET, 1, true), 1 + #"api_key: ", "the file the user saved is the intended copy")
    end
  end

  for _, command in ipairs({ "VaultEdit", "VaultView" }) do
    tests[command .. " never persists the decrypted buffer it opens"] = function()
      local dirs = persistence_dirs()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local source = H.new_file_buffer(dirs.base, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
      local scratch = H.open_scratch(command, source)
      H.assert_hardened(scratch)
      yes(H.text(scratch):find(SECRET, 1, true), "precondition: the scratch holds the decrypted value")
      vim.cmd("silent! preserve")
      assert_no_persisted_copy(dirs)
      eq(H.grep_under(dirs.base, SECRET), {}, command .. " must not write a plaintext temporary file")
    end
  end

  tests["Create never persists the buffer it opens"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local path = dirs.base .. "/new.yml"
    vim.cmd("VaultCreate " .. vim.fn.fnameescape(path))
    local scratch = vim.api.nvim_get_current_buf()
    H.assert_hardened(scratch)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "api_key: " .. SECRET })
    vim.cmd("silent! preserve")
    assert_no_persisted_copy(dirs)
    vim.cmd("silent write")
    assert_no_persisted_copy(dirs)
    eq(H.grep_under(dirs.base, SECRET), {}, "not even the created file may hold plaintext")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
  end

  --- Undo history ----------------------------------------------------------

  for _, scope in ipairs({ "whole", "inline" }) do
    tests[scope .. " Decrypt leaves no undo history to recover from"] = function()
      local dirs = persistence_dirs()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local input = scope == "whole" and H.envelope("api_key: " .. SECRET .. "\n") or H.inline(SECRET, "api_key:")
      local buf = H.new_file_buffer(dirs.base, "vault.yml", input)
      local before = H.lines(buf)
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return H.text(buf):find(SECRET, 1, true) ~= nil
      end)
      local after = H.lines(buf)
      vim.cmd("silent! undo")
      eq(H.lines(buf), after, "undo must not step back across a decrypt")
      no(vim.deep_equal(H.lines(buf), before))
      -- An undo file written while the buffer holds plaintext records the
      -- *ciphertext* the change replaced, which is not a secret.
      vim.cmd("silent! wundo " .. vim.fn.fnameescape(dirs.undo .. "/manual"))
      assert_no_persisted_copy(dirs)
    end
  end

  tests["whole Encrypt leaves no undo history holding the plaintext"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_file_buffer(H.temp_dir(), "plain.yml", { "api_key: " .. SECRET })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    local after = H.lines(buf)
    vim.cmd("silent! undo")
    eq(H.lines(buf), after, "undo must not bring the plaintext back")
  end

  ---A decrypt/encrypt round trip on a file that was never plaintext on disk.
  ---
  ---`with_cleared_undo` empties the undo *tree*, so nothing in the session can
  ---reach the plaintext — but Neovim still serialises the text a change replaced
  ---into the persistent undo file. Persistent undo must therefore stay off for a
  ---buffer that held a secret, or the user's next `:w` writes a plaintext copy
  ---they never asked for.
  tests["a decrypt then encrypt round trip must not write plaintext to the undo file"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(dirs.base, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    vim.cmd("silent write")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"), "precondition: only ciphertext was ever saved")
    assert_no_persisted_copy(dirs)
  end

  ---Abandoning a decrypt by reloading the file is the other way out of a managed
  ---buffer, and the undo state does not become harmless just because a read
  ---happened: `:edit!` records the reload as an undoable change, so the undo tree
  ---still holds the plaintext the reload replaced. Handing persistent undo back
  ---there puts that plaintext in the undo file on the next ordinary write.
  for _, variant in ipairs({ "reloaded", "file deleted" }) do
    local name = "abandoning a decrypt by reloading writes no plaintext to the undo file"
    tests[name .. " (" .. variant .. ")"] = function()
      local dirs = persistence_dirs()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local buf, path = H.new_file_buffer(dirs.base, "only.yml", H.envelope("api_key: " .. SECRET .. "\n"))
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return H.text(buf):find(SECRET, 1, true) ~= nil
      end)

      if variant == "file deleted" then
        vim.fn.delete(path)
      end
      vim.cmd("silent! edit!")

      -- Discarding the undo tree must not make a freshly read buffer look edited.
      no(vim.bo[buf].modified, "clearing the undo history must leave 'modified' as the read left it")

      -- Every route back in time, not just `:undo`: 'undofile' is handed back
      -- here, so anything the undo state can still reach is also persistable.
      for _, back in ipairs({ "undo", "earlier 1f", "earlier 100", "normal! 10g-" }) do
        vim.cmd("silent! " .. back)
        no(H.text(buf):find(SECRET, 1, true) ~= nil, ":" .. back .. " must not bring the plaintext back")
      end
      vim.cmd("silent! later 999")
      vim.cmd("silent! redo")

      -- Real edits and real writes, which is when Neovim serialises undo state.
      vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "6161" })
      pcall(vim.cmd, "silent write")
      vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed: line" })
      pcall(vim.cmd, "silent write")
      vim.cmd("silent! preserve")
      assert_no_persisted_copy(dirs)
    end
  end

  ---A buffer someone else made 'nomodifiable' cannot have its undo history
  ---cleared at all, so the history stays reachable in memory — there is nothing
  ---the plugin can do about that without overriding the user's own setting. What
  ---it can do is refuse to hand persistent undo back, so none of it can be
  ---written out. Reachable whenever something marks files read-only on read,
  ---which people do for generated or vendored trees.
  tests["a reload that cannot clear its undo history keeps persistent undo off"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_file_buffer(dirs.base, "nomod.yml", H.envelope("api_key: " .. SECRET .. "\nb: two\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)

    H.sabotage({ "BufReadPost", "BufNewFile" }, {
      buffer = buf,
      once = true,
      callback = function()
        vim.bo[buf].modifiable = false
      end,
    })
    vim.cmd("silent! edit!")

    -- The whole point: the clear could not run, so persistent undo must not be
    -- restored. `silent!` swallows the error the clearing attempt raises, so
    -- "it ran without throwing" proves nothing and is not what is checked.
    no(vim.bo[buf].undofile, "persistent undo must stay off when the history could not be thrown away")

    -- Real edits and real writes, which is when undo state would be serialised.
    vim.bo[buf].modifiable = true
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "6161" })
    pcall(vim.cmd, "silent write")
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed: line" })
    pcall(vim.cmd, "silent write")
    vim.cmd("silent! preserve")
    assert_no_persisted_copy(dirs)
  end

  --- Hardening that cannot be established at all ----------------------------

  ---Each of these sabotages one hardening step and checks the plugin gives up
  ---rather than continuing half-protected. The levers are deliberately crude —
  ---an `OptionSet` handler that puts an option back, or a buffer made
  ---'nomodifiable' — because the failures they stand in for (a hostile autocmd,
  ---a plugin fighting over buffer options) look exactly like this from inside.

  tests["a View whose guards cannot be installed shows nothing at all"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local source = H.new_file_buffer(H.temp_dir(), "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    local windows = #vim.api.nvim_list_wins()

    H.sabotage("OptionSet", {
      pattern = "buftype",
      callback = function()
        pcall(function()
          vim.bo.buftype = "nofile"
        end)
      end,
    })
    H.command_fails("VaultView")

    eq(#vim.api.nvim_list_wins(), windows, "no window may be opened for an unguarded view")
    for _, buf in ipairs(vim.api.nvim_list_bufs()) do
      if buf ~= source and vim.api.nvim_buf_is_loaded(buf) then
        no(H.text(buf):find(SECRET, 1, true) ~= nil, "no buffer may be left holding the viewed plaintext")
      end
    end
    yes(H.encrypted(source), "the source must be untouched")
  end

  ---A buffer whose hardening will not take must not be given the plaintext at
  ---all: `'swapfile'` back on with a secret already in the buffer means Neovim
  ---writes a swap file straight away, without the user asking for anything.
  ---
  ---Both halves need a real swap directory and a non-zero 'updatecount', or
  ---headless Neovim never writes a swap file and the assertions cannot see the
  ---leak they exist for.
  tests["a buffer that cannot be hardened keeps its ciphertext"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(dirs.base, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    local before = H.read_file(path)

    -- Hardening cannot be established at all.
    H.sabotage("OptionSet", {
      pattern = "swapfile",
      callback = function()
        pcall(function()
          vim.bo.swapfile = true
        end)
      end,
    })
    H.command_fails("VaultDecrypt")

    yes(H.encrypted(buf), "the decrypted content must not be put in a buffer that cannot hold it safely")
    no(H.text(buf):find(SECRET, 1, true) ~= nil)
    eq(H.read_file(path), before)
    vim.cmd("silent! preserve")
    assert_no_persisted_copy(dirs)
  end

  tests["a buffer that cannot be secured is not left half managed"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(dirs.base, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    local before = H.read_file(path)

    -- Sabotage 'buftype', not 'swapfile': hardening then succeeds and the
    -- plaintext does land, so this exercises the dangerous path where the
    -- *session* is what fails to install.
    H.sabotage("OptionSet", {
      pattern = "buftype",
      callback = function()
        pcall(function()
          vim.bo.buftype = ""
        end)
      end,
    })
    H.command_fails("VaultDecrypt")
    yes(H.notification_contains("could not be secured"), H.notification_text())
    yes(H.text(buf):find(SECRET, 1, true) ~= nil, "precondition: the plaintext did land in the buffer")

    -- Neither managed nor still hooked: a half-installed session would leave a
    -- `BufWriteCmd` behind with nothing to service it.
    eq(require("ansible-vault.plaintext").get(buf), nil, "no session may be registered")
    eq(#vim.api.nvim_get_autocmds({ event = "BufWriteCmd", buffer = buf }), 0, "no write hook may be left behind")
    eq(#vim.api.nvim_get_autocmds({ event = "FileWriteCmd", buffer = buf }), 0)

    -- The part that matters: failing to secure a buffer is no reason to unsecure
    -- it. Putting 'swapfile' back here would persist the secret immediately.
    no(vim.bo[buf].swapfile, "'swapfile' must stay off while the buffer holds plaintext")
    no(vim.bo[buf].undofile, "'undofile' must stay off too")
    eq(vim.fn.swapname(buf), "", "no swap file may exist for it")
    vim.cmd("silent! preserve")
    assert_no_persisted_copy(dirs)
    eq(H.read_file(path), before)
  end

  for _, command in ipairs({ "VaultCreate", "VaultEdit" }) do
    tests[command .. " opens nothing when the buffer cannot be secured"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local dir = H.temp_dir()
      local source, path = H.new_file_buffer(dir, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
      local before = H.read_file(path)

      H.sabotage("OptionSet", {
        pattern = "swapfile",
        callback = function()
          pcall(function()
            vim.bo.swapfile = true
          end)
        end,
      })
      H.command_fails(command == "VaultCreate" and ("VaultCreate " .. vim.fn.fnameescape(dir .. "/new.yml")) or command)

      for _, buf in ipairs(vim.api.nvim_list_bufs()) do
        if buf ~= source and vim.api.nvim_buf_is_loaded(buf) then
          no(H.text(buf):find(SECRET, 1, true) ~= nil, "no unprotected buffer may hold the plaintext")
        end
      end
      eq(vim.fn.filereadable(dir .. "/new.yml"), 0, "nothing may be created on disk")
      eq(H.read_file(path), before)
    end
  end

  ---Encrypting one value replaces plaintext, so that plaintext becomes undo
  ---history. The buffer's 'undofile' is turned off for good, which is what keeps
  ---it off disk — but the history itself is kept, because `:undo` bringing back
  ---the value you just encrypted is what people expect, and it never leaves
  ---memory.
  tests["range Encrypt keeps its undo in memory and off disk"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "api_key: " .. SECRET, "other: keep" }
    local buf, path = H.new_file_buffer(dirs.base, "vars.yml", input)
    yes(vim.bo[buf].undofile, "precondition: an ordinary file buffer has persistent undo on")

    vim.cmd("1VaultEncrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "api_key: !vault |"
    end)

    no(vim.bo[buf].undofile, "the buffer that held the value keeps persistent undo off from now on")
    vim.cmd("silent write")
    yes(H.read_file(path):find("!vault", 1, true) ~= nil)
    assert_no_persisted_copy(dirs)

    -- Undo is deliberately still usable, in memory only.
    vim.cmd("silent! undo")
    eq(H.lines(buf), input, ":undo must still bring the value back for the user")
    vim.cmd("silent! preserve")
    assert_no_persisted_copy(dirs)
  end

  tests["in-place encryption keeps undo usable for later edits"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_file_buffer(H.temp_dir(), "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)

    -- Losing cross-session undo for a buffer that held a secret is the accepted
    -- cost; losing undo altogether is not.
    local before = #H.lines(buf)
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "6161" })
    vim.cmd("silent! undo")
    eq(#H.lines(buf), before, "undo must still work for edits made after the encryption")
  end

  tests["protecting one buffer does not disable undo files for other buffers"] = function()
    local dirs = persistence_dirs()
    local fake = H.create_fake_vault()
    H.reset_config(fake)

    -- A managed buffer is open and decrypted the whole time.
    local managed = H.new_file_buffer(dirs.base, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(managed):find(SECRET, 1, true) ~= nil
    end)

    local path = dirs.base .. "/ordinary.txt"
    H.write_file(path, "line one\nline two\n")
    local other = H.open_file(path)
    yes(vim.bo[other].undofile, "an unrelated buffer must keep its own 'undofile'")
    yes(vim.bo[other].swapfile, "and its own 'swapfile'")
    eq(vim.bo[other].buftype, "")
    vim.api.nvim_buf_set_lines(other, 0, 1, false, { "line one edited" })
    vim.cmd("silent write")

    local wrote_undo = false
    for _, file in ipairs(H.files_under(dirs.undo)) do
      wrote_undo = wrote_undo or file:find("ordinary", 1, true) ~= nil
    end
    yes(wrote_undo, "the fix must not stop ordinary files getting undo files")
    assert_no_persisted_copy(dirs)
  end

  tests["reopening a file in a fresh buffer gets persistent undo back"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    vim.o.undofile = true
    local buf, path = H.new_file_buffer(dir, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    no(vim.bo[buf].undofile, "this buffer held a secret, so it keeps persistent undo off")

    vim.cmd("silent write")
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    local reopened = H.open_file(path)
    yes(vim.bo[reopened].undofile, "a fresh buffer on the same file is an ordinary buffer again")
  end

  --- Writes that would go around the plugin's writer --------------------------

  ---`acwrite` routes `:w`, `:w {path}` and `:saveas` through `BufWriteCmd`, but it
  ---does not cover a partial-range write or an append: `:1w {file}` raises
  ---`FileWriteCmd` and `:w >> {file}` raises `FileAppendCmd`. With no handler,
  ---Neovim writes those lines itself — unencrypted, non-atomically, and with the
  ---umask's permissions instead of 0600.
  local escapes = {
    { "partial write", "1write" },
    { "partial range write", "1,2write" },
    { "partial write with bang", "1write!" },
    { "append", "write >>" },
    { "partial append", "1write >>" },
  }

  local function managed_buffer(kind, dir, fake)
    if kind == "decrypted" then
      local buf = H.new_file_buffer(dir, "vault.yml", H.envelope("a: " .. SECRET .. "\nb: two\nc: three\n"))
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return H.text(buf):find(SECRET, 1, true) ~= nil
      end)
      return buf
    end
    if kind == "Edit scratch" then
      local source = H.new_file_buffer(dir, "vault.yml", H.envelope("a: " .. SECRET .. "\nb: two\nc: three\n"))
      return H.open_scratch("VaultEdit", source)
    end
    if kind == "View float" then
      local source = H.new_file_buffer(dir, "vault.yml", H.envelope("a: " .. SECRET .. "\nb: two\n"))
      return H.open_scratch("VaultView", source)
    end
    vim.cmd("VaultCreate " .. vim.fn.fnameescape(dir .. "/created.yml"))
    local buf = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "a: " .. SECRET, "b: two", "c: three" })
    return buf
  end

  for _, kind in ipairs({ "decrypted", "Edit scratch", "Create buffer", "View float" }) do
    for _, escape in ipairs(escapes) do
      tests[("a %s refuses a %s"):format(kind, escape[1])] = function()
        local fake = H.create_fake_vault()
        H.reset_config(fake)
        local dir = H.temp_dir()
        local buf = managed_buffer(kind, dir, fake)
        yes(H.text(buf):find(SECRET, 1, true) ~= nil, "precondition: the buffer holds the plaintext")

        local target = dir .. "/escaped"
        -- An append to a file that already exists, so a refusal is the only
        -- reason nothing can be added to it.
        H.write_file(target, "pre-existing\n")
        H.write_fails(("silent %s %s"):format(escape[2], vim.fn.fnameescape(target)))
        eq(H.read_file(target), "pre-existing\n", "not one byte of plaintext may reach the target")
      end
    end
  end

  tests["a released buffer is an ordinary buffer for partial writes again"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local buf = H.new_file_buffer(dir, "vault.yml", H.envelope("a: " .. SECRET .. "\nb: two\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)

    -- The buffer is ciphertext and no longer managed, so refusing its writes
    -- would be the fix overreaching.
    local target = dir .. "/part"
    vim.cmd("silent 1write " .. vim.fn.fnameescape(target))
    yes(H.read_file(target):match("^%$ANSIBLE_VAULT;"), "a partial write of ciphertext is the user's business")
  end

  tests["partial writes from unrelated buffers keep working"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()

    -- Registered per buffer, so a managed buffer being open must not change what
    -- any other buffer can do.
    local managed = H.new_file_buffer(dir, "vault.yml", H.envelope("a: " .. SECRET .. "\nb: two\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(managed):find(SECRET, 1, true) ~= nil
    end)

    H.new_buffer({ "ordinary: one", "ordinary: two", "ordinary: three" })
    local partial = dir .. "/u_partial"
    vim.cmd("silent 1write " .. vim.fn.fnameescape(partial))
    eq(H.read_file(partial), "ordinary: one\n")

    local appended = dir .. "/u_append"
    H.write_file(appended, "first\n")
    vim.cmd("silent 1write >> " .. vim.fn.fnameescape(appended))
    eq(H.read_file(appended), "first\nordinary: one\n")

    local whole = dir .. "/u_whole"
    vim.cmd("silent write " .. vim.fn.fnameescape(whole))
    eq(H.read_file(whole), "ordinary: one\nordinary: two\nordinary: three\n")
  end

  tests["a whole-buffer save of decrypted content still works and is owner-only"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local buf = H.new_file_buffer(dir, "vault.yml", H.envelope("a: " .. SECRET .. "\nb: two\nc: three\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)

    -- Refusing partial writes must not get in the way of the explicit save the
    -- whole command exists for.
    for _, command in ipairs({ "write", "%write" }) do
      local target = dir .. "/asked-for-" .. command:gsub("%%", "pct")
      vim.cmd(("silent %s %s"):format(command, vim.fn.fnameescape(target)))
      yes(H.read_file(target):find(SECRET, 1, true) ~= nil, command .. " is the explicit save the user asked for")
      eq(vim.fn.getfperm(target), "rw-------", command .. " must go through the plugin's 0600 atomic write")
    end
  end

  tests["the View float refuses every form of write"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local source = H.new_file_buffer(dir, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    local view = H.open_scratch("VaultView", source)
    yes(H.text(view):find(SECRET, 1, true) ~= nil, "precondition: the float holds the decrypted value")

    local target = dir .. "/viewed"
    for _, command in ipairs({ "write", "write!", "saveas", "saveas!", "%write", "1write", "write >>" }) do
      H.write_fails(("silent %s %s"):format(command, vim.fn.fnameescape(target)))
      eq(vim.fn.filereadable(target), 0, ":" .. command .. " must not put the viewed plaintext on disk")
    end
    -- With no file name of its own there is nothing for a bare `:w` to write to
    -- either.
    H.write_fails("silent write")
    eq(H.files_under(dir), { dir .. "/vault.yml" }, "viewing must create no file at all")
  end

  --- When protection may be dropped ----------------------------------------

  tests["whole Encrypt restores normal write behaviour but range Encrypt does not"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_file_buffer(H.temp_dir(), "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    eq(vim.bo[buf].buftype, "acwrite")
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    eq(vim.bo[buf].buftype, "", "the whole buffer is ciphertext again, so writes are ordinary again")
    yes(vim.bo[buf].swapfile, "'swapfile' comes back with it")
  end

  tests["encrypting one value does not release a buffer that still holds plaintext"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline(SECRET, "api_key:")
    table.insert(input, "other: " .. SECRET .. "-two")
    local buf = H.new_file_buffer(H.temp_dir(), "vars.yml", input)
    vim.cmd("1,3VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "api_key: " .. SECRET
    end)
    eq(vim.bo[buf].buftype, "acwrite")

    vim.cmd("1VaultEncrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "api_key: !vault |"
    end)
    eq(vim.bo[buf].buftype, "acwrite", "one value being encrypted proves nothing about the rest of the buffer")
    H.assert_hardened(buf)
  end

  ---A decrypted buffer is released only once a read has replaced the plaintext.
  ---
  ---`BufUnload` fires while the plaintext is still in the buffer, so restoring
  ---'swapfile' there would write the secret out on the way past.
  tests["reloading a decrypted buffer restores protection only after the read"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local buf = H.new_file_buffer(dir, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    eq(vim.bo[buf].buftype, "acwrite")

    vim.cmd("silent! edit!")
    yes(H.encrypted(buf), "the reload should bring the ciphertext back")
    eq(vim.bo[buf].buftype, "", "normal write behaviour returns once the plaintext is gone")
    yes(vim.bo[buf].swapfile)
    eq(H.grep_under(dir, SECRET), {}, "the round trip must leave no plaintext beside the file")
  end

  tests["re-editing a decrypted buffer whose file was deleted still releases it"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(H.temp_dir(), "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    vim.fn.delete(path)
    vim.cmd("silent! edit!")
    -- Only `BufNewFile` fires for a file that is no longer there, and the buffer
    -- is just as empty as after a successful read, so it is released.
    eq(H.lines(buf), { "" }, "the plaintext is gone either way")
    eq(vim.bo[buf].buftype, "")
  end

  tests["a read that truly fails leaves the buffer fail closed"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(H.temp_dir(), "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)

    -- Neither BufReadPost nor BufNewFile can fire for this, so the hardened
    -- options stay and the write path has no owner left.
    vim.fn.delete(path)
    vim.fn.mkdir(path, "p")
    pcall(vim.cmd, "silent! edit!")
    eq(vim.bo[buf].buftype, "acwrite", "a failed read must leave the buffer protected")
    no(vim.bo[buf].swapfile)
    H.write_fails("silent write")
    H.write_fails("silent write!")
  end

  --- Passwords ------------------------------------------------------------

  tests["an interactive password reaches the child through the environment only"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local typed = "TYPED-SECRET-a41c"
    H.patch(vim.fn, "inputsecret", function()
      return typed
    end)
    local buf = H.new_buffer({ "api_key: value" })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)

    yes(H.log_has_line(fake.log, "ENVPW:set"), "the password must be handed over in the environment")
    for _, line in ipairs(H.log_lines(fake.log)) do
      no(line:find(typed, 1, true) ~= nil, "the password must never appear in argv: " .. line)
    end

    local helper
    for _, line in ipairs(H.log_lines(fake.log)) do
      local candidate = line:match("^ARG:(/.+)$") or line:match("^ARG:[^@]+@(/.+)$")
      if candidate and candidate:find("askpass", 1, true) then
        helper = candidate
      end
    end
    yes(helper ~= nil, "a helper script should stand in for the password file")
    no(H.read_file(helper):find(typed, 1, true) ~= nil, "the helper script must contain no secret")
  end

  tests["a typed password is never reused by the next operation"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local prompts = 0
    H.patch(vim.fn, "inputsecret", function()
      prompts = prompts + 1
      return "secret"
    end)
    local buf = H.new_buffer({ "api_key: value" })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    eq(prompts, 1)
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "api_key: value"
    end)
    eq(prompts, 2, "each operation must ask again rather than cache the password")
  end

  tests["an unavailable password helper fails closed without writing the password"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local helper, helper_dir = H.askpass_path()
    -- The helper is cached once installed, so remove it: without this the patch
    -- below would be bypassed and the test would pass for the wrong reason.
    vim.fn.delete(helper)
    local stdpath = vim.fn.stdpath
    H.patch(vim.fn, "stdpath", function(what)
      if what == "run" then
        return ""
      end
      return stdpath(what)
    end)
    local typed = "NEVER-ON-DISK-77b2"
    H.patch(vim.fn, "inputsecret", function()
      return typed
    end)

    local buf = H.new_buffer({ "api_key: value" })
    H.command_fails("VaultEncrypt")
    yes(H.notification_contains("without writing it to disk"), H.notification_text())
    no(H.encrypted(buf), "nothing may be encrypted with a password that could not be passed safely")
    eq(H.calls(fake), 0, "the child must not be started at all")
    eq(H.grep_under(helper_dir, typed), {}, "no password file fallback may be written")
    no(H.notification_text():find(typed, 1, true) ~= nil, "the password must not be echoed back")
  end

  tests["a credential file the user supplied still works without the helper"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local stdpath = vim.fn.stdpath
    H.patch(vim.fn, "stdpath", function(what)
      if what == "run" then
        return ""
      end
      return stdpath(what)
    end)
    local buf = H.new_buffer({ "api_key: value" })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end, "a configured password file needs no helper script")
  end

  --- Failure messages -----------------------------------------------------

  tests["a failed operation reports stderr but never stdout or credentials"] = function()
    local fake = H.create_fake_vault()
    local config = H.reset_config(fake)
    local buf = H.new_buffer(H.envelope("api_key: " .. SECRET .. "\n"))

    -- The fake writes the credential path to stderr, so a summary that is not
    -- redacted will contain it.
    vim.env.FAKE_VAULT_FAIL = config.password_files
    H.command_fails("VaultDecrypt")

    local text = H.notification_text()
    yes(H.notification_contains("PRIVATE-STDERR-CANARY"), "stderr is the one thing that may be summarised")
    no(text:find("PRIVATE-STDOUT-CANARY", 1, true) ~= nil, "stdout can be plaintext and must never be shown")
    no(text:find(config.password_files, 1, true) ~= nil, "the credential path must be redacted: " .. text)
    yes(text:find("<redacted>", 1, true) ~= nil, "redaction should be visible, not silent")
    no(
      text:find(fake.path, 1, true) ~= nil or text:find("--vault-password-file", 1, true) ~= nil,
      "no argv in messages"
    )
    yes(H.encrypted(buf), "a failed decrypt must leave the ciphertext alone")
  end

  tests["a failed operation does not reveal a typed password"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local typed = "TYPED-SECRET-9dd0"
    H.patch(vim.fn, "inputsecret", function()
      return typed
    end)
    local buf = H.new_buffer(H.envelope("api_key: " .. SECRET .. "\n"))
    vim.env.FAKE_VAULT_FAIL = typed
    H.command_fails("VaultDecrypt")
    no(H.notification_text():find(typed, 1, true) ~= nil, "the password must be redacted out of the summary")
    yes(H.encrypted(buf))
  end

  tests["a failure message is capped instead of flooding messages"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    H.new_buffer(H.envelope("api_key: " .. SECRET .. "\n"))
    vim.env.FAKE_VAULT_FAIL = string.rep("noise ", 400)
    H.command_fails("VaultDecrypt")
    yes(#H.notification_text() < 1200, "a chatty child must not flood :messages")
  end

  --- Explicit saves -------------------------------------------------------

  tests["saving a decrypted buffer elsewhere keeps the original buffer unsaved"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local buf, path = H.new_file_buffer(dir, "vault.yml", H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "extra: line" })

    local other = dir .. "/copy.yml"
    vim.cmd("silent write " .. vim.fn.fnameescape(other))
    yes(H.read_file(other):find(SECRET, 1, true) ~= nil, "an explicit :w {file} saves what the user asked for")
    yes(vim.bo[buf].modified, ":w {file} copies the text; it does not save this buffer")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"), "the buffer's own file is still untouched ciphertext")

    H.write_fails("silent write " .. vim.fn.fnameescape(other))
    vim.cmd("silent write! " .. vim.fn.fnameescape(other))
  end

  ---An unnamed buffer has nothing for a write to be "other" than, so `:w {path}`
  ---is that buffer being saved. Anything else makes the first `:w {path}` leave
  ---the buffer looking unsaved and the second one clear it, for no reason the
  ---user can see.
  tests["saving an unnamed decrypted buffer to a path adopts that path"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local buf = H.new_buffer(H.envelope("api_key: " .. SECRET .. "\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find(SECRET, 1, true) ~= nil
    end)
    eq(vim.api.nvim_buf_get_name(buf), "", "precondition: the buffer has no name")
    eq(vim.bo[buf].buftype, "acwrite", "an unnamed buffer must be managed too")

    local path = dir .. "/saved.yml"
    vim.cmd("silent write " .. vim.fn.fnameescape(path))
    yes(H.read_file(path):find(SECRET, 1, true) ~= nil, "the decrypted bytes are what was asked for")
    eq(vim.api.nvim_buf_get_name(buf), path, "the buffer should now be visiting that file")
    no(vim.bo[buf].modified, "saving an unnamed buffer to a path saves it")

    -- And it keeps saving itself, without needing the path again.
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "extra: line" })
    vim.cmd("silent write")
    yes(H.read_file(path):find("extra: line", 1, true) ~= nil)
    no(vim.bo[buf].modified)

    -- Now that it has a name, another path is a copy again.
    local other = dir .. "/copy.yml"
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "more: lines" })
    vim.cmd("silent write " .. vim.fn.fnameescape(other))
    yes(vim.bo[buf].modified, ":w {other} on a named buffer is still only a copy")
    eq(vim.api.nvim_buf_get_name(buf), path)
  end
end
