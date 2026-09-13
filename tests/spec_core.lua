---Command semantics: what each of the six commands acts on, and what `:w` then
---saves. Driven entirely through `vim.cmd`, because the commands are the whole
---public interface.
---@param H table
---@param tests table
return function(H, tests)
  local eq, yes, no = H.assert_eq, H.assert_true, H.assert_false

  local function fixture(value, label)
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope(value or "plain: old\n", nil, label))
    return fake, buf, path
  end

  --- Public surface ---------------------------------------------------------

  tests["public surface is setup only and six commands exist without setup"] = function()
    local script = H.temp_dir() .. "/public.lua"
    H.write_file(
      script,
      string.format(
        [[
vim.opt.runtimepath:prepend(%q)
vim.cmd('runtime plugin/ansible-vault.lua')
local module = require('ansible-vault')
assert(vim.deep_equal(vim.tbl_keys(module), {'setup'}), vim.inspect(vim.tbl_keys(module)))
local names = {'VaultCreate','VaultEncrypt','VaultDecrypt','VaultView','VaultEdit','VaultRekey'}
for _, name in ipairs(names) do assert(vim.fn.exists(':' .. name) == 2, name) end
module.setup({})
module.setup({})
for _, name in ipairs(names) do assert(vim.fn.exists(':' .. name) == 2, name) end
io.stdout:write('PUBLIC_OK\n'); io.stdout:flush()
]],
        H.root
      )
    )
    local result = vim.system({ vim.v.progpath, "--headless", "-u", "NONE", "-l", script }):wait(10000)
    eq(result.code, 0, result.stderr)
    yes(result.stdout:find("PUBLIC_OK", 1, true))
  end

  tests["opening ciphertext has no automatic operation"] = function()
    local fake, buf = fixture()
    eq(vim.bo[buf].buftype, "")
    yes(H.encrypted(buf))
    eq(H.calls(fake), 0)
  end

  --- Scope -----------------------------------------------------------------

  tests["whole Encrypt uses current buffer and leaves saving to user"] = function()
    local fake = H.create_fake_vault()
    local config = H.reset_config(fake)
    local buf, path = H.new_file_buffer(fake.dir, "plain.yml", { "alpha: one", "beta: two" })
    local before = H.read_file(path)
    vim.api.nvim_buf_set_mark(buf, "<", 2, 0, {})
    vim.api.nvim_buf_set_mark(buf, ">", 2, 4, {})
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    eq(H.read_file(path), before)
    yes(H.log_has_line(fake.log, "ARG:" .. config.password_files), "space-containing path must be one argv item")
    yes(H.log_has_line(fake.log, "CONSUMED"), "fake must consume credentials")
    vim.cmd("silent write")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "alpha: one"
    end)
    eq(H.lines(buf), { "alpha: one", "beta: two" })
  end

  tests["whole header wins and stale visual marks do not select inline scope"] = function()
    local _, buf = fixture()
    vim.api.nvim_buf_set_mark(buf, "<", 2, 0, {})
    vim.api.nvim_buf_set_mark(buf, ">", 2, 1, {})
    vim.api.nvim_win_set_cursor(0, { 1, 0 })
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "plain: old"
    end)
    eq(H.lines(buf), { "plain: old" })
  end

  tests["no-range Encrypt after inline Decrypt is whole, never foldback"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("secret")
    table.insert(input, "other: keep")
    local buf, path = H.new_file_buffer(fake.dir, "inline.yml", input)
    local before = H.read_file(path)
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "password: secret"
    end)
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    eq(H.calls(fake, "encrypt"), 1)
    eq(H.calls(fake, "encrypt_string"), 0)
    eq(H.read_file(path), before)
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "password: secret"
    end)
    eq(H.lines(buf), { "password: secret", "other: keep" })
  end

  local refusals = {
    "VaultDecrypt",
    "VaultView",
    "VaultEdit",
    "VaultRekey --new-vault-password-file /none",
  }
  for _, command in ipairs(refusals) do
    tests[command .. " refuses plaintext or cursor outside a block"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local input = H.inline("secret")
      table.insert(input, "other: untouched")
      local buf = H.new_buffer(input)
      vim.api.nvim_win_set_cursor(0, { 4, 0 })
      H.command_fails(command)
      eq(H.lines(buf), input)
      eq(vim.api.nvim_get_current_buf(), buf)
      eq(H.calls(fake), 0)
    end
  end

  for name, range in pairs({ truncated = "1,2", multiple = "1,6", neighbor = "1,4" }) do
    tests["inline scope rejects " .. name .. " range without modifying neighbors"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local input = H.inline("one", "first:")
      vim.list_extend(input, name == "multiple" and H.inline("two", "second:") or { "other: keep" })
      local buf = H.new_buffer(input)
      H.command_fails(range .. "VaultDecrypt")
      eq(H.lines(buf), input)
    end
  end

  tests["range Encrypt refuses a selection that cuts a nested value in half"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "vars:", "  inner: one", "  other: two" }
    local buf = H.new_buffer(input)
    H.command_fails("1VaultEncrypt")
    eq(H.lines(buf), input, "encrypting a parent key would orphan its children")
    eq(H.calls(fake), 0)
  end

  tests["range Encrypt rejects multiple plaintext keys before mutation"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "first: one", "second: two" }
    local buf = H.new_buffer(input)
    H.command_fails("1,2VaultEncrypt")
    eq(H.lines(buf), input)
    eq(H.calls(fake), 0)
  end

  --- Decrypt saves plaintext ------------------------------------------------

  for _, scope in ipairs({ "whole", "inline" }) do
    tests[scope .. " Decrypt write saves plaintext without a second prompt"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake, { password_files = false })
      local prompts = 0
      H.patch(vim.fn, "inputsecret", function()
        prompts = prompts + 1
        return "secret"
      end)
      local input = scope == "whole" and H.envelope("plain: old\n") or H.inline("old", "plain:")
      local buf, path = H.new_file_buffer(fake.dir, scope .. ".yml", input)
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return H.lines(buf)[1] == "plain: old"
      end)
      H.assert_hardened(buf)
      eq(vim.bo[buf].buftype, "acwrite")
      vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "plain: intentionally saved" })
      vim.cmd("silent write")
      eq(H.read_file(path), "plain: intentionally saved\n")
      eq(prompts, 1)
      eq(H.calls(fake, "encrypt"), 0)
      eq(H.calls(fake, "encrypt_string"), 0)
      H.assert_hardened(buf)
      no(vim.bo[buf].modified)
    end
  end

  tests["a decrypted file reopened later is an ordinary plaintext file"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope("plain: old\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "plain: old"
    end)
    vim.cmd("silent write")
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
    local reopened = H.open_file(path)
    eq(H.lines(reopened), { "plain: old" })
    eq(vim.bo[reopened].buftype, "", "a plain file must not be adopted on open")
    yes(vim.bo[reopened].swapfile, "no leftover hardening on an ordinary file")
    eq(H.calls(fake, "decrypt"), 1, "reopening must not run ansible-vault")
  end

  --- Byte fidelity ---------------------------------------------------------

  -- Expected values are literals written here, never computed by the code under
  -- test: a round trip through the implementation's own parse/format pair would
  -- agree with itself no matter how wrong it was.
  local byte_values = {
    { "no trailing newline", "single" },
    { "one trailing newline", "single\n" },
    { "three trailing newlines", "one\ntwo\n\n\n" },
    { "embedded blank line", "a\n\nb\n" },
    { "leading spaces", "  indented\nnext\n" },
    { "crlf bytes", "a\r\nb\r\n" },
    { "tab and control bytes", "tab\there\n" },
    { "multiline without trailing newline", "one\ntwo" },
    { "colon and hash", "a: b # not a comment" },
    { "yaml keyword", "true" },
  }

  for _, case in ipairs(byte_values) do
    tests["inline Decrypt then range Encrypt round-trips " .. case[1]] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local input = H.inline(case[2])
      table.insert(input, "other: keep")
      local buf = H.new_buffer(input)
      vim.cmd("1,3VaultDecrypt")
      H.wait_until(function()
        return not vim.deep_equal(H.lines(buf), input)
      end)
      eq(H.lines(buf)[#H.lines(buf)], "other: keep", "the neighbour must be untouched")

      local stdin = fake.dir .. "/stdin"
      vim.env.FAKE_VAULT_STDIN_LOG = stdin
      vim.cmd("1," .. (#H.lines(buf) - 1) .. "VaultEncrypt")
      H.wait_until(function()
        return H.text(buf):find("!vault", 1, true) ~= nil
      end)
      eq(H.read_file(stdin), case[2], "the value must survive decrypt -> encrypt byte for byte")
      eq(H.lines(buf)[1], "password: !vault |", "the key must come from the buffer, not from ansible-vault")
      eq(H.lines(buf)[#H.lines(buf)], "other: keep")
    end
  end

  tests["an empty inline value decrypts but cannot be re-encrypted"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("")
    table.insert(input, "other: keep")
    local buf = H.new_buffer(input)
    vim.cmd("1,3VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == 'password: ""'
    end)
    local before = H.lines(buf)
    local modified = vim.bo[buf].modified
    H.command_fails("1VaultEncrypt")
    yes(H.notification_contains("Encryption failed"), H.notification_text())
    eq(H.lines(buf), before, "empty inline encryption must leave the value and its neighbor unchanged")
    eq(vim.bo[buf].modified, modified)
    eq(H.calls(fake, "encrypt_string"), 1)

    -- The failure must finish the operation, not leave the buffer locked.
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "password: retry" })
    vim.cmd("1VaultEncrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "password: !vault |"
    end)
  end

  tests["a value ending in a newline survives at end of file without a final EOL"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local path = fake.dir .. "/noeol.yml"
    H.write_file(path, table.concat(H.inline("value\n"), "\n"))
    local buf = H.open_file(path)
    no(vim.bo[buf].endofline, "precondition: the fixture has no final newline")
    vim.cmd("1,3VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] ~= "password: !vault |"
    end)
    local stdin = fake.dir .. "/stdin"
    vim.env.FAKE_VAULT_STDIN_LOG = stdin
    vim.cmd("1," .. #H.lines(buf) .. "VaultEncrypt")
    H.wait_until(function()
      return H.text(buf):find("!vault", 1, true) ~= nil
    end)
    eq(H.read_file(stdin), "value\n", "the trailing newline is part of the value, not of the file")
  end

  local whole_bytes = {
    { "empty file", "" },
    { "no trailing newline", "plain: old" },
    { "several trailing newlines", "plain: old\n\n\n" },
    { "crlf file", "a: 1\r\nb: 2\r\n" },
  }
  for _, case in ipairs(whole_bytes) do
    tests["whole Decrypt writes plaintext byte for byte: " .. case[1]] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local buf, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope(case[2]))
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return not H.encrypted(buf)
      end)
      vim.cmd("silent write")
      eq(H.read_file(path), case[2], "the decrypted bytes are what :w must save")
    end
  end

  ---Content ending in a carriage return with no final newline.
  ---
  ---Only content that *ends* with a newline can be `dos`. Without one the last
  ---line has no line ending for its carriage return to live in, so treating it
  ---as half of a CRLF pair and writing the buffer back with 'noendofline' drops
  ---that byte: "a\r" becomes "a". Every one of these goes through a different
  ---writer, and none of them may lose it.
  local cr_values = { { "trailing CR", "a\r" }, { "bare CR", "\r" }, { "CRLF then bare CR", "a\r\nb\r" } }

  for _, case in ipairs(cr_values) do
    tests["whole Decrypt then :w keeps a " .. case[1]] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local buf, path = H.new_file_buffer(fake.dir, "vault.yml", H.envelope(case[2]))
      vim.cmd("VaultDecrypt")
      H.wait_until(function()
        return not H.encrypted(buf)
      end)
      vim.cmd("silent write")
      eq(H.read_file(path), case[2], "the decrypted bytes are what :w must save")
    end

    tests["whole Edit re-encrypts a " .. case[1] .. " unchanged"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local source = H.new_file_buffer(fake.dir, "vault.yml", H.envelope(case[2]))
      local scratch = H.open_scratch("VaultEdit", source)
      local stdin = fake.dir .. "/stdin"
      vim.env.FAKE_VAULT_STDIN_LOG = stdin
      -- Saving without editing anything at all must be a byte-for-byte identity.
      vim.cmd("silent write")
      H.wait_until(function()
        return not vim.api.nvim_buf_is_valid(scratch)
      end, "an unedited whole-file Edit save should still consume the plaintext scratch")
      eq(vim.api.nvim_get_current_buf(), source)
      no(vim.bo[source].modified)
      eq(H.read_file(stdin), case[2], "an unedited Edit must re-encrypt exactly what it decrypted")
    end

    tests["inline Edit re-encrypts a " .. case[1] .. " unchanged"] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local input = H.inline(case[2])
      table.insert(input, "other: keep")
      local source = H.new_buffer(input)
      vim.api.nvim_win_set_cursor(0, { 1, 0 })
      local scratch = H.open_scratch("VaultEdit", source)
      local stdin = fake.dir .. "/stdin"
      vim.env.FAKE_VAULT_STDIN_LOG = stdin
      vim.cmd("silent write")
      H.wait_until(function()
        return not vim.api.nvim_buf_is_valid(scratch)
      end, "an unedited inline Edit save should still consume the plaintext scratch")
      eq(vim.api.nvim_get_current_buf(), source)
      yes(vim.bo[source].modified, "the re-encrypted inline block still needs a normal source write")
      eq(H.read_file(stdin), case[2], "an unedited inline Edit must re-encrypt exactly what it decrypted")
    end
  end

  --- Structure preserved by range Encrypt ----------------------------------

  local shapes = {
    { "key", { "password: secret" }, "secret", "password: !vault |" },
    { "quoted-key-comment", { [['a: b': "sec#ret" # comment]] }, "sec#ret", "'a: b': !vault |" },
    -- The apostrophe is data, so the trailing comment is still a comment and
    -- never part of the secret handed to ansible-vault.
    { "apostrophe-comment", { [[password: don't # deployment password]] }, "don't", "password: !vault |" },
    { "nested-list-key", { "    - password: value" }, "value", "    - password: !vault |" },
    { "bare-list", { "    - value" }, "value", "    - !vault |" },
    { "scalar", { "plain-value" }, "plain-value", nil },
    { "literal-strip", { "password: |-", "  first", "  second" }, "first\nsecond", "password: !vault |" },
    { "literal-clip", { "password: |", "  first", "  second" }, "first\nsecond\n", "password: !vault |" },
    { "literal-keep", { "password: |+", "  first", "", "" }, "first\n\n\n", "password: !vault |" },
    {
      "nested-multiline",
      { "  - 'a: b': |-", "      first", "      second" },
      "first\nsecond",
      "  - 'a: b': !vault |",
    },
    { "leading-space", { "password: |2-", "    indented", "  normal" }, "  indented\nnormal", "password: !vault |" },
  }
  for _, case in ipairs(shapes) do
    tests["range Encrypt preserves value bytes " .. case[1]] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local buf = H.new_buffer(case[2])
      local stdin = fake.dir .. "/stdin"
      vim.env.FAKE_VAULT_STDIN_LOG = stdin
      vim.cmd("1," .. #case[2] .. "VaultEncrypt")
      H.wait_until(function()
        return H.text(buf):find("!vault", 1, true) ~= nil
      end)
      eq(H.read_file(stdin), case[3], "encrypt_string must receive only the YAML value, byte-for-byte")
      if case[4] then
        eq(H.lines(buf)[1], case[4], "raw key/list/indent structure must survive")
      end
      eq(H.calls(fake, "encrypt"), 0)
    end
  end

  --- View ------------------------------------------------------------------

  tests["View is readonly protected disposable and preserves source filetype"] = function()
    local _, source, path = fixture()
    vim.bo[source].filetype = "yaml"
    local before = H.read_file(path)
    local view = H.open_scratch("VaultView", source)
    H.assert_hardened(view)
    no(vim.bo[view].modifiable, "the view must not be editable")
    yes(vim.bo[view].readonly, "the view must be read-only")
    -- `acwrite` rather than `nofile`: `nofile` only stops `:w`, because the buffer
    -- has no file of its own. `:w {path}` from a `nofile` buffer is not
    -- intercepted at all and writes the decrypted content straight out.
    eq(vim.bo[view].buftype, "acwrite")
    eq(vim.bo[view].filetype, "yaml")
    -- The trailing blank line is the value's own final newline, shown rather than
    -- trimmed: the float reports the exact decrypted bytes.
    eq(H.lines(view), { "plain: old", "" })
    H.write_fails("silent write")
    vim.api.nvim_win_close(0, true)
    no(vim.api.nvim_buf_is_valid(view), "View must wipe when closed")
    eq(H.read_file(path), before)
    yes(H.encrypted(source))
    eq(vim.bo[source].buftype, "", "viewing must not adopt the source buffer")
  end

  tests["inline View operates on an explicit single block without changing source"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("secret")
    table.insert(input, "other: keep")
    local source = H.new_buffer(input)
    local view = H.open_scratch("1,3VaultView", source)
    eq(H.lines(view), { "secret" })
    H.assert_hardened(view)
    eq(H.lines(source), input)
    no(vim.bo[view].modifiable)
  end

  --- Edit -----------------------------------------------------------------

  tests["whole Edit saves then returns to its refreshed ciphertext source"] = function()
    local fake, source, path = fixture()
    local scratch = H.open_scratch("VaultEdit", source)
    H.assert_hardened(scratch)
    eq(vim.bo[scratch].buftype, "acwrite")
    yes(vim.api.nvim_buf_get_name(scratch):find("ansible-vault://", 1, true) == 1)

    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: first", "extra: line" })
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end, "a successful Edit save should dispose its plaintext scratch")
    eq(vim.api.nvim_get_current_buf(), source)
    no(vim.bo[source].modified)
    yes(H.encrypted(source))
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))

    -- A further edit opens a fresh protected session from the returned source.
    local second = H.open_scratch("VaultEdit", source)
    vim.api.nvim_buf_set_lines(second, 0, -1, false, { "plain: second", "extra: line" })
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(second)
    end)
    eq(H.calls(fake, "encrypt"), 2)

    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(source)[1] == "plain: second"
    end)
    eq(H.lines(source), { "plain: second", "extra: line" })
  end

  tests["inline Edit returns to a preexisting dirty source and only splices its block"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "before: original" }
    vim.list_extend(input, H.inline("old"))
    table.insert(input, "after: original")
    local source, path = H.new_file_buffer(fake.dir, "inline.yml", input)
    local disk = H.read_file(path)
    vim.api.nvim_buf_set_lines(source, 0, 1, false, { "before: user-dirty" })
    vim.api.nvim_win_set_cursor(0, { 3, 10 })
    local source_win = vim.api.nvim_get_current_win()
    local windows = #vim.api.nvim_list_wins()
    local scratch = H.open_scratch("VaultEdit", source)
    eq(#vim.api.nvim_list_wins(), windows + 1, "inline Edit opens a window of its own for the value")
    eq(H.lines(scratch), { "old" })
    H.assert_hardened(scratch)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end, "a successful inline save should dispose its plaintext scratch")

    eq(#vim.api.nvim_list_wins(), windows, "the window it opened must go with the session it ended")
    eq(vim.api.nvim_get_current_win(), source_win, "the cursor belongs back where the value came from")
    eq(vim.api.nvim_get_current_buf(), source)
    eq(H.lines(source)[1], "before: user-dirty", "edits made before opening must be kept as they were")
    eq(H.lines(source)[#H.lines(source)], "after: original")
    yes(H.text(source):find("password: !vault |", 1, true))
    yes(vim.bo[source].modified, "the source is left for the user to save")
    eq(H.read_file(path), disk, "inline Edit must never save source YAML")

    vim.cmd("silent write")
    no(vim.bo[source].modified)
    no(H.read_file(path) == disk)
  end

  ---Closing the window an inline session opened beats leaving a duplicate of the
  ---window below it. Being the *last* window turns the same act into a way of
  ---quitting Neovim, which no save asked for.
  tests["an inline Edit alone in the last window keeps that window"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "before: keep" }
    vim.list_extend(input, H.inline("old"))
    local source = H.new_buffer(input)
    vim.api.nvim_win_set_cursor(0, { 2, 0 })
    local scratch = H.open_scratch("VaultEdit", source)

    vim.cmd("only")
    eq(#vim.api.nvim_list_wins(), 1)
    eq(vim.api.nvim_get_current_buf(), scratch, "precondition: the scratch is alone on screen")

    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "new" })
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end, "a successful inline save should dispose its plaintext scratch")

    eq(#vim.api.nvim_list_wins(), 1, "the only window must survive the save that ended the session")
    eq(vim.api.nvim_get_current_buf(), source, "and must show the source the value went back into")
    yes(H.text(source):find("password: !vault |", 1, true) ~= nil)
  end

  tests["inline Edit writes back the exact bytes it was given"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("one\ntwo\n")
    table.insert(input, "other: keep")
    local source = H.new_buffer(input)
    vim.api.nvim_win_set_cursor(0, { 1, 0 })
    local scratch = H.open_scratch("VaultEdit", source)
    eq(H.lines(scratch), { "one", "two" })
    yes(vim.bo[scratch].endofline, "a value ending in a newline keeps it in 'endofline'")
    local stdin = fake.dir .. "/stdin"
    vim.env.FAKE_VAULT_STDIN_LOG = stdin
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end, "a successful inline byte-fidelity save should consume the plaintext scratch")
    eq(vim.api.nvim_get_current_buf(), source)
    eq(H.read_file(stdin), "one\ntwo\n", "an unedited value must be re-encrypted unchanged")
  end

  --- Create ---------------------------------------------------------------

  tests["Create first write opens ciphertext and mode 0600"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local path = fake.dir .. "/new vault.yml"
    vim.cmd("VaultCreate " .. vim.fn.fnameescape(path))
    local scratch = vim.api.nvim_get_current_buf()
    H.assert_hardened(scratch)
    eq(vim.bo[scratch].buftype, "acwrite")
    eq(vim.api.nvim_buf_get_name(scratch), "ansible-vault://" .. path)
    eq(vim.fn.filereadable(path), 0)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "secret: created" })
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end, "a successful Create save should dispose its plaintext scratch")
    eq(vim.api.nvim_buf_get_name(0), path)
    eq(vim.bo[0].buftype, "")
    yes(H.read_file(path):match("^%$ANSIBLE_VAULT;"))
    eq(vim.fn.getfperm(path), "rw-------")
  end

  tests["a relative VaultCreate keeps its target across :cd"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local original_dir = H.temp_dir()
    local target = original_dir .. "/vault.yml"
    vim.cmd("cd " .. vim.fn.fnameescape(original_dir))
    vim.cmd("VaultCreate vault.yml")
    local scratch = vim.api.nvim_get_current_buf()
    eq(vim.api.nvim_buf_get_name(scratch), "ansible-vault://" .. target)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "secret: created" })

    local other_dir = H.temp_dir()
    vim.cmd("cd " .. vim.fn.fnameescape(other_dir))
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end, "a successful relative Create should dispose its scratch")

    yes(H.read_file(target):match("^%$ANSIBLE_VAULT;"))
    eq(vim.fn.filereadable(other_dir .. "/vault.yml"), 0, ":cd must not retarget a Create write")
    eq(vim.api.nvim_buf_get_name(0), target)
  end

  tests["Create never clears an existing unsaved buffer at the target name"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local path = fake.dir .. "/not-created.yml"
    local original = H.open_file(path)
    vim.api.nvim_buf_set_lines(original, 0, -1, false, { "user data" })
    pcall(vim.cmd, "VaultCreate " .. vim.fn.fnameescape(path))
    eq(H.lines(original), { "user data" })
    yes(vim.bo[original].modified)
    eq(vim.fn.filereadable(path), 0)
  end

  tests["Create refuses existing files and a target appearing before first save"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local path = fake.dir .. "/exists.yml"
    H.write_file(path, "keep me\n")
    H.command_fails("VaultCreate " .. vim.fn.fnameescape(path))
    eq(H.read_file(path), "keep me\n")
    local new = fake.dir .. "/new.yml"
    vim.cmd("VaultCreate " .. vim.fn.fnameescape(new))
    local scratch = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "mine" })
    H.write_file(new, "other writer\n")
    H.write_fails()
    eq(H.read_file(new), "other writer\n")
    yes(vim.bo[scratch].modified)
    vim.cmd("silent write!")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end)
    yes(H.read_file(new):match("^%$ANSIBLE_VAULT;"), ":w! is how the user overrides that refusal")
  end

  for _, mode in ipairs({ "whole", "inline", "create" }) do
    tests[mode .. " Edit or Create rejects redirected writes"] = function()
      local fake, source, path = fixture()
      if mode == "inline" then
        vim.api.nvim_buf_set_lines(source, 0, -1, false, H.inline("old"))
      end
      local scratch
      if mode == "create" then
        vim.cmd("VaultCreate " .. vim.fn.fnameescape(fake.dir .. "/new.yml"))
        scratch = vim.api.nvim_get_current_buf()
      else
        scratch = H.open_scratch("VaultEdit", source)
      end
      local before = H.read_file(path)
      vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "modified" })
      local target = fake.dir .. "/redirect.yml"
      H.write_fails("silent write " .. vim.fn.fnameescape(target))
      eq(vim.fn.filereadable(target), 0)
      eq(H.read_file(path), before)
      yes(vim.bo[scratch].modified)
      H.write_fails("silent write! " .. vim.fn.fnameescape(target))
      eq(vim.fn.filereadable(target), 0, ":w! must not turn a redirected write into a plaintext copy")
    end
  end

  tests["fixed-target Create and Edit sessions recover from refused :saveas"] = function()
    for _, mode in ipairs({ "whole", "inline", "create" }) do
      local fake, source, path = fixture()
      if mode == "inline" then
        vim.api.nvim_buf_set_lines(source, 0, -1, false, H.inline("old"))
        vim.api.nvim_win_set_cursor(0, { 1, 0 })
      end

      local target = path
      local scratch
      if mode == "create" then
        target = fake.dir .. "/created.yml"
        vim.cmd("VaultCreate " .. vim.fn.fnameescape(target))
        scratch = vim.api.nvim_get_current_buf()
      else
        scratch = H.open_scratch("VaultEdit", source)
      end
      local scratch_name = vim.api.nvim_buf_get_name(scratch)
      vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "modified" })

      local redirect = fake.dir .. "/redirect.yml"
      for _, command in ipairs({ "saveas", "saveas!" }) do
        H.write_fails("silent " .. command .. " " .. vim.fn.fnameescape(redirect))
        eq(vim.api.nvim_buf_get_name(scratch), scratch_name, mode .. " must restore its protected scratch identity")
        yes(vim.bo[scratch].modified, mode .. " must retain plaintext edits for a normal retry")
        eq(vim.fn.filereadable(redirect), 0, mode .. " must not export plaintext through :" .. command)
      end

      vim.cmd("silent write")
      H.wait_until(function()
        return not vim.api.nvim_buf_is_valid(scratch)
      end, mode .. " should still be saveable after :saveas is refused")
      if mode == "inline" then
        yes(H.text(source):find("!vault", 1, true) ~= nil)
      else
        yes(H.read_file(target):match("^%$ANSIBLE_VAULT;"))
      end
    end
  end

  ---`:saveas` renames the buffer, so the session's idea of what it writes has to
  ---follow it. Otherwise the next plain `:w` refuses, or worse writes to the old
  ---path, and `:wq` cannot exit.
  tests["saveas on a decrypted buffer keeps it saveable afterwards"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local dir = H.temp_dir()
    local buf = H.new_file_buffer(dir, "vault.yml", H.envelope("plain: old\n"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "plain: old"
    end)

    local renamed = dir .. "/renamed.yml"
    vim.cmd("silent saveas " .. vim.fn.fnameescape(renamed))
    eq(vim.api.nvim_buf_get_name(buf), renamed, "the buffer should now be visiting the new path")
    eq(H.read_file(renamed), "plain: old\n")
    no(vim.bo[buf].modified)

    -- A plain `:w` must keep working against the new name.
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "extra: line" })
    vim.cmd("silent write")
    eq(H.read_file(renamed), "plain: old\nextra: line\n")
    no(vim.bo[buf].modified)

    -- And another path is still only a copy.
    local copy = dir .. "/copy.yml"
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "more: lines" })
    vim.cmd("silent write " .. vim.fn.fnameescape(copy))
    yes(H.read_file(copy):find("more: lines", 1, true) ~= nil, "the copy holds the current text")
    yes(vim.bo[buf].modified, ":w {other} copies the text and leaves this buffer unsaved")
    eq(vim.api.nvim_buf_get_name(buf), renamed)

    -- `:wq` has to be able to finish the job.
    vim.cmd("split")
    local windows = #vim.api.nvim_list_wins()
    vim.cmd("silent wq")
    eq(#vim.api.nvim_list_wins(), windows - 1, ":wq must exit after a successful write")
    eq(H.read_file(renamed), "plain: old\nextra: line\nmore: lines\n")
  end

  ---A `!vault` list item has no key. The plugin produces those itself, so every
  ---verb has to accept one back: the prefix is rebuilt from the buffer, and
  ---`--stdin-name` only names the key Ansible echoes back, which is discarded.
  tests["a keyless list item survives Edit"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "  - !vault |" }
    for _, line in ipairs(H.envelope("listed")) do
      table.insert(input, "      " .. line)
    end
    table.insert(input, "  - other")
    local source = H.new_buffer(input)
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    local scratch = H.open_scratch("VaultEdit", source)
    eq(H.lines(scratch), { "listed" }, "the scratch holds just the value")
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "rotated" })
    local stdin = fake.dir .. "/stdin"
    vim.env.FAKE_VAULT_STDIN_LOG = stdin
    vim.cmd("silent write")
    H.wait_until(function()
      return not vim.api.nvim_buf_is_valid(scratch)
    end)

    eq(vim.api.nvim_get_current_buf(), source)
    eq(H.lines(source)[1], "  - !vault |", "the list dash and indentation must come back unchanged")
    eq(H.lines(source)[#H.lines(source)], "  - other")
    eq(H.read_file(stdin), "rotated")
  end

  ---A keyless list item owns no mapping past its dash, so the literal block it
  ---decrypts into is indented from the sequence. Two extra spaces there are not
  ---cosmetic: YAML reads them as part of every line of the value.
  tests["a keyless list item round-trips a multiline value"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "- !vault |" }
    for _, line in ipairs(H.envelope("first\nsecond\n")) do
      table.insert(input, "    " .. line)
    end
    table.insert(input, "- other")
    local buf = H.new_buffer(input)

    vim.cmd("1," .. (#input - 1) .. "VaultDecrypt")
    H.wait_until(function()
      return H.text(buf):find("!vault", 1, true) == nil
    end)
    eq(
      H.lines(buf),
      { "- |2+", "  first", "  second", "- other" },
      "the body belongs under the sequence, not past the dash"
    )

    local stdin = fake.dir .. "/stdin"
    vim.env.FAKE_VAULT_STDIN_LOG = stdin
    vim.cmd("1,3VaultEncrypt")
    H.wait_until(function()
      return H.text(buf):find("!vault", 1, true) ~= nil
    end)
    eq(H.read_file(stdin), "first\nsecond\n", "the value must survive decrypt -> encrypt byte for byte")
    eq(H.lines(buf)[1], "- !vault |", "the list dash must come from the buffer")
    eq(H.lines(buf)[#H.lines(buf)], "- other")
  end

  tests["a hand-written keyless envelope indented two spaces decrypts"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = { "- !vault |" }
    for _, line in ipairs(H.envelope("listed")) do
      table.insert(input, "  " .. line)
    end
    local buf = H.new_buffer(input)
    vim.cmd("1," .. #input .. "VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "- listed"
    end, "a two-space payload under a keyless list item is a valid block")
  end

  --- Rekey ----------------------------------------------------------------

  for _, label in ipairs({ "", "prod" }) do
    tests["native Rekey preserves envelope " .. (label == "" and "1.1" or "1.2 label")] = function()
      local fake, buf, path = fixture("plain: old\n", label ~= "" and label or nil)
      local new = H.make_password_file(fake.dir, "new-secret", "new pass")
      local before = H.read_file(path)
      vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
      H.wait_until(function()
        return H.read_file(path) ~= before and H.encrypted(buf)
      end)
      eq(H.calls(fake, "rekey"), 1)
      eq(H.calls(fake, "decrypt"), 0, "whole Rekey must use native rekey, not decrypt/encrypt")
      no(H.log_has_line(fake.log, "ARG:--encrypt-vault-id"))
      yes(H.log_has_line(fake.log, "ARG:" .. (label ~= "" and (label .. "@" .. new) or new)))
      eq(
        H.read_file(path):match("^[^\n]+"),
        label ~= "" and "$ANSIBLE_VAULT;1.2;AES256;prod" or "$ANSIBLE_VAULT;1.1;AES256"
      )
      yes(H.log_has_line(fake.log, "ENV:ANSIBLE_VAULT_ENCRYPT_IDENTITY="), "rekey must not inherit an encrypt identity")
    end
  end

  tests["after a whole Rekey the new password opens the file and the old one does not"] = function()
    local fake, buf, path = fixture()
    local old = H.make_password_file(fake.dir, "secret")
    local new = H.make_password_file(fake.dir, "new-secret", "new pass")
    local before = H.read_file(path)
    vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return H.read_file(path) ~= before and H.encrypted(buf)
    end)

    vim.cmd("VaultDecrypt --vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return H.lines(buf)[1] == "plain: old"
    end, "the NEW password must open the rekeyed file")

    -- A copy, so the old password is tried against untouched ciphertext rather
    -- than against a buffer this test already decrypted.
    local copy = fake.dir .. "/copy.yml"
    H.write_file(copy, H.read_file(path))
    H.open_file(copy)
    H.command_fails("VaultDecrypt --vault-password-file " .. vim.fn.fnameescape(old))
    yes(H.encrypted(0), "the OLD password must no longer open the file")
  end

  -- "reported success but produced nothing usable" is the case that matters:
  -- `ansible-vault rekey` removes and recreates its target, so publishing
  -- whatever came back would destroy the only copy of the ciphertext.
  for _, failure in ipairs({ "fail", "invalid", "empty", "truncated" }) do
    tests["a whole Rekey that " .. failure .. "s leaves the original ciphertext alone"] = function()
      local fake, buf, path = fixture()
      local new = H.make_password_file(fake.dir, "new-secret", "new pass")
      local before = H.read_file(path)
      vim.env.FAKE_VAULT_ACTION = "rekey"
      if failure == "fail" then
        vim.env.FAKE_VAULT_FAIL = "rekey exploded"
      else
        vim.env.FAKE_VAULT_OUTPUT = failure
      end
      H.command_fails("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
      eq(H.read_file(path), before, "a failed rekey must not touch the target")
      yes(H.encrypted(buf))
    end
  end

  tests["Rekey refuses a modified buffer and a buffer with no file"] = function()
    local fake, buf = fixture()
    local new = H.make_password_file(fake.dir, "new-secret", "new pass")
    vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "dirty" })
    H.command_fails("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
    eq(H.calls(fake, "rekey"), 0)

    H.new_buffer(H.envelope("plain: old\n"))
    H.command_fails("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
    eq(H.calls(fake, "rekey"), 0)
  end

  tests["Rekey without a new credential fails before running anything"] = function()
    local fake = fixture()
    H.command_fails("VaultRekey")
    eq(H.calls(fake), 0)
  end

  tests["inline Rekey never inserts intermediate plaintext or saves source"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("PRIVATE-inline\n\n", "password:", nil, "prod")
    table.insert(input, "other: keep")
    local buf, path = H.new_file_buffer(fake.dir, "inline.yml", input)
    local before = H.read_file(path)
    local new = H.make_password_file(fake.dir, "rotated", "new")
    local plaintext_seen = false
    vim.api.nvim_buf_attach(buf, false, {
      on_lines = function()
        plaintext_seen = plaintext_seen or H.text(buf):find("PRIVATE-inline", 1, true) ~= nil
      end,
    })
    vim.cmd("1,3VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return not vim.deep_equal(H.lines(buf), input)
    end)
    no(plaintext_seen, "the rotation plaintext must never reach the buffer")
    eq(H.read_file(path), before)
    eq(H.lines(buf)[#H.lines(buf)], "other: keep")
    eq(H.calls(fake, "rekey"), 0)
    eq(H.calls(fake, "decrypt"), 1)
    eq(H.calls(fake, "encrypt_string"), 1)
    no(vim.bo[buf].buftype == "acwrite", "rekey must not leave the source managed as plaintext")

    -- The value now opens with the new password and no longer with the old one.
    vim.cmd("1,3VaultDecrypt --vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return H.text(buf):find("PRIVATE%-inline")
    end, "the rekeyed value must open with the NEW password")
  end

  tests["a keyless list item survives Rekey with a real password change"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local old = H.make_password_file(fake.dir, "secret")
    local new = H.make_password_file(fake.dir, "rotated", "new pass")
    local input = { "  - !vault |" }
    for _, line in ipairs(H.envelope("listed")) do
      table.insert(input, "      " .. line)
    end
    table.insert(input, "  - other")
    local buf = H.new_buffer(input)

    vim.cmd("1,3VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return not vim.deep_equal(H.lines(buf), input)
    end)
    eq(H.lines(buf)[1], "  - !vault |", "the list dash and indentation must survive the rotation")
    eq(H.lines(buf)[#H.lines(buf)], "  - other")

    -- Judged the only honest way: the new password opens it and the old one
    -- does not.
    vim.cmd("1,3VaultDecrypt --vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return H.lines(buf)[1] == "  - listed"
    end, "the NEW password must open the rekeyed value")

    local again = H.new_buffer(H.lines(buf))
    vim.cmd("1VaultEncrypt --vault-password-file " .. vim.fn.fnameescape(new))
    H.wait_until(function()
      return H.lines(again)[1] == "  - !vault |"
    end)
    H.command_fails("1,3VaultDecrypt --vault-password-file " .. vim.fn.fnameescape(old))
    eq(H.lines(again)[1], "  - !vault |", "the OLD password must not open it")
  end

  tests["inline Rekey leaves the old block in place when re-encryption fails"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local input = H.inline("value", "password:")
    table.insert(input, "other: keep")
    local buf = H.new_buffer(input)
    local new = H.make_password_file(fake.dir, "rotated", "new")
    vim.env.FAKE_VAULT_ACTION = "encrypt_string"
    vim.env.FAKE_VAULT_FAIL = "no re-encryption for you"
    H.command_fails("1,3VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
    eq(H.lines(buf), input, "a failed second stage must leave the original block")
  end
end
