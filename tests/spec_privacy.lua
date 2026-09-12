---@param H table Shared helpers from tests/helpers.lua
---@param tests table Registry the driver runs
return function(H, tests)
  local vault = require("ansible-vault")
  local assert_eq = H.assert_eq
  local assert_true = H.assert_true
  local assert_false = H.assert_false
  local wait_until = H.wait_until
  local write_file = H.write_file
  local read_file = H.read_file
  local temp_dir = H.temp_dir
  local create_fake_vault = H.create_fake_vault
  local reset_config = H.reset_config
  local new_file_buffer = H.new_file_buffer
  local new_buffer = H.new_buffer
  local notification_contains = H.notification_contains
  --- Privacy ----------------------------------------------------------------

  tests["decrypt hardens the buffer against on-disk persistence"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local updatecount = vim.o.updatecount
    vim.o.updatecount = 200 -- headless Neovim disables swap files by default

    local dir = temp_dir()
    local buf = new_file_buffer(dir, "vault.yml", { "$ANSIBLE_VAULT;1.1;AES256", "ENC:plain" })

    assert_true(vim.bo[buf].swapfile, "precondition: the encrypted buffer should start with swap enabled")

    vault.decrypt(buf)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "plain: value"
    end, "buffer was not decrypted")

    assert_false(vim.bo[buf].swapfile, "'swapfile' must be off while the buffer holds plaintext")
    assert_false(vim.bo[buf].undofile, "'undofile' must be off while the buffer holds plaintext")
    assert_eq(vim.bo[buf].buftype, "acwrite", "writes must be routed through the plugin")
    assert_eq(vim.fn.swapname(buf), "", "no swap file may exist for a decrypted buffer")

    vim.o.updatecount = updatecount
  end

  tests["writing a decrypted buffer stores ciphertext"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf, path = new_file_buffer(dir, "vault.yml", { "$ANSIBLE_VAULT;1.1;AES256", "ENC:plain" })

    vault.decrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "plain: value"
    end, "buffer was not decrypted")

    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "plain: topsecret" })
    vim.cmd("silent write")

    wait_until(function()
      return read_file(path):match("^%$ANSIBLE_VAULT") ~= nil
    end, "write did not produce ciphertext")

    local written = read_file(path)
    assert_true(written:match("^%$ANSIBLE_VAULT;1%.1;AES256"), "file should start with a vault header")
    assert_false(written:match("\nplain: topsecret\n") ~= nil, "plaintext must not appear in the written file")
    assert_eq(
      vim.api.nvim_buf_get_lines(buf, 0, -1, false),
      { "plain: topsecret" },
      "the buffer should stay decrypted for further editing"
    )
  end

  tests["an unnamed decrypted buffer cannot be written out as plaintext"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "ENC:plain" })
    vault.decrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "plain: value"
    end, "buffer was not decrypted")

    assert_eq(vim.bo[buf].buftype, "acwrite", "an unnamed buffer must be protected too")

    local dir = temp_dir()
    local path = dir .. "/leak.yml"
    vim.cmd("silent write " .. vim.fn.fnameescape(path))

    wait_until(function()
      return vim.fn.filereadable(path) == 1
    end, ":w {file} on an unnamed buffer did not produce a file")

    assert_true(read_file(path):match("^%$ANSIBLE_VAULT"), "an unnamed buffer must encrypt on :w {file} too")

    -- `:w {file}` names the buffer, so drop it rather than leaving a modified
    -- buffer for whichever test runs next.
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
  end

  tests["writing a decrypted buffer to another path also encrypts"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf = new_file_buffer(dir, "vault.yml", { "$ANSIBLE_VAULT;1.1;AES256", "ENC:plain" })

    vault.decrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "plain: value"
    end, "buffer was not decrypted")

    local other = dir .. "/copy.yml"
    vim.cmd("silent write " .. vim.fn.fnameescape(other))

    wait_until(function()
      return vim.fn.filereadable(other) == 1
    end, ":w {file} did not produce a file")

    assert_true(read_file(other):match("^%$ANSIBLE_VAULT"), ":w {file} must encrypt too, not bypass the plugin")
  end

  tests["encrypt restores normal write handling"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf = new_file_buffer(dir, "vault.yml", { "$ANSIBLE_VAULT;1.1;AES256", "ENC:plain" })

    vault.decrypt(buf)
    wait_until(function()
      return vim.bo[buf].buftype == "acwrite"
    end, "buffer did not enter plaintext mode")

    vault.encrypt(buf)
    wait_until(function()
      return vim.bo[buf].buftype == ""
    end, "buffer did not leave plaintext mode")

    assert_true(vim.bo[buf].swapfile, "'swapfile' should be restored once the buffer holds ciphertext again")
    assert_true(vault.is_buffer_encrypted(buf), "buffer should report itself encrypted")
  end

  tests["decrypting an inline string enters inline mode and write restores the block"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf, path = new_file_buffer(dir, "vars.yml", {
      "keep: me",
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:hunter2",
      "trailing: value",
    })

    vim.api.nvim_win_set_cursor(0, { 2, 0 })
    vault.decrypt()

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 1, 2, false)[1] == "password: hunter2"
    end, "inline value was not decrypted")

    assert_false(vim.bo[buf].swapfile, "'swapfile' must be off once an inline value is decrypted")
    assert_eq(vim.bo[buf].buftype, "acwrite", "inline decryption must route writes through the plugin")
    assert_eq(
      vim.api.nvim_buf_get_lines(buf, 0, -1, false),
      { "keep: me", "password: hunter2", "trailing: value" },
      "surrounding lines must be preserved"
    )

    vim.cmd("silent write")

    -- Leaving plaintext mode is the observable end of the write; the file already
    -- contained "!vault" before the test started, so its content proves nothing.
    wait_until(function()
      return vim.bo[buf].buftype == ""
    end, "write did not complete")

    local written = read_file(path)
    assert_false(written:match("password: hunter2") ~= nil, "the decrypted value must not reach disk")
    assert_true(written:match("^keep: me\n") ~= nil, "unrelated lines must be written unchanged")
    assert_true(written:match("trailing: value") ~= nil, "unrelated lines must be written unchanged")
    assert_true(written:match("!vault") ~= nil, "the vault block must be restored")
  end

  tests["multiple decrypted inline values are all restored on write"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf, path = new_file_buffer(dir, "vars.yml", {
      "first: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:alpha",
      "middle: plain",
      "second: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:beta",
    })

    vim.api.nvim_win_set_cursor(0, { 5, 0 })
    vault.decrypt()
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 4, 5, false)[1] == "second: beta"
    end, "second value was not decrypted")

    vim.api.nvim_win_set_cursor(0, { 1, 0 })
    vault.decrypt()
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "first: alpha"
    end, "first value was not decrypted")

    assert_eq(
      vim.api.nvim_buf_get_lines(buf, 0, -1, false),
      { "first: alpha", "middle: plain", "second: beta" },
      "both values should be decrypted in place"
    )

    vim.cmd("silent write")
    wait_until(function()
      return vim.bo[buf].buftype == ""
    end, "write did not complete")

    local written = read_file(path)
    assert_false(written:match("first: alpha") ~= nil, "the first value must be written as a vault block")
    assert_false(written:match("second: beta") ~= nil, "the second value must be written as a vault block")
    assert_true(written:match("middle: plain") ~= nil, "untouched lines must be written unchanged")
    assert_eq(select(2, written:gsub("!vault", "")), 2, "both vault blocks must be restored")
  end

  tests["inline restore preserves dos line endings"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local path = dir .. "/crlf.yml"
    write_file(
      path,
      "keep: me\r\npassword: !vault |\r\n          $ANSIBLE_VAULT;1.1;AES256\r\n          ENCSTR:hunter2\r\n"
    )
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    assert_eq(vim.bo[buf].fileformat, "dos", "precondition: the fixture should be detected as dos")

    vim.api.nvim_win_set_cursor(0, { 2, 0 })
    vault.decrypt()
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 1, 2, false)[1] == "password: hunter2"
    end, "CRLF inline value was not decrypted")

    vim.cmd("silent write")
    wait_until(function()
      return vim.bo[buf].buftype == ""
    end, "write did not complete")

    local written = read_file(path)
    assert_true(written:match("keep: me\r\n") ~= nil, "dos line endings must be preserved")
    assert_false(written:match("password: hunter2") ~= nil, "the value must be written as a vault block")
    assert_true(written:match("!vault") ~= nil, "the vault block must be restored")
  end

  tests["failed decryption does not surface process output"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    local buf = new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "ENC:x" })

    -- stdout is plaintext for a decrypt that fails late; only stderr may be shown.
    vim.env.FAKE_VAULT_FAIL = "wrong password"
    vault.decrypt(buf)

    wait_until(function()
      return notification_contains("Decryption failed")
    end, "no failure was reported")

    assert_true(notification_contains("fake vault error"), "stderr should be reported")
    assert_false(notification_contains("plain: value"), "process stdout must never be shown")
  end

  tests["debug logging redacts credential arguments"] = function()
    local redact = require("ansible-vault.cli").redact_argv
    assert_eq(
      redact({ "ansible-vault", "encrypt", "--vault-password-file", "/home/u/.secret", "-" }),
      "ansible-vault encrypt --vault-password-file <redacted> -"
    )
    assert_eq(
      redact({ "ansible-vault", "encrypt", "--vault-id", "prod@/home/u/.secret", "--encrypt-vault-id", "prod" }),
      "ansible-vault encrypt --vault-id <redacted> --encrypt-vault-id prod"
    )
  end
end
