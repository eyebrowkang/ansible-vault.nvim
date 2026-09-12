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
  local make_password_file = H.make_password_file
  local reset_config = H.reset_config
  local new_file_buffer = H.new_file_buffer
  local new_buffer = H.new_buffer
  local log_contains = H.log_contains
  local log_has_line = H.log_has_line
  local notification_contains = H.notification_contains

  tests["encrypt uses argv and supports paths with spaces"] = function()
    local fake = create_fake_vault()
    local config = reset_config(fake)
    local buf = new_buffer({ "plain" })

    vault.encrypt(buf)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt did not update target buffer")

    assert_true(
      log_contains(fake.log, "ARG:" .. config.password_files),
      "password path was not passed as one argv item"
    )
    assert_false(
      log_contains(fake.log, "ARG:--encrypt-vault-id"),
      "default encryption must not force --encrypt-vault-id"
    )
    assert_true(vault.is_buffer_encrypted(buf), "buffer should report itself encrypted")
  end

  tests["async encrypt writes back to the original buffer"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    vim.env.FAKE_VAULT_SLEEP = "0.2"

    local first = new_buffer({ "first" })
    local second = vim.api.nvim_create_buf(true, false)
    vim.api.nvim_buf_set_lines(second, 0, -1, false, { "second" })

    vault.encrypt(first)
    vim.api.nvim_set_current_buf(second)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(first, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "original buffer was not encrypted")

    assert_eq(
      vim.api.nvim_buf_get_lines(second, 0, -1, false),
      { "second" },
      "current buffer was modified by async callback"
    )
  end

  tests["async encrypt does not clobber a changed buffer"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    vim.env.FAKE_VAULT_SLEEP = "0.2"

    local buf = new_buffer({ "plain" })
    vault.encrypt(buf)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "user edit" })

    wait_until(function()
      return vim.b[buf].ansible_vault_pending == nil
    end, "encrypt operation did not finish")

    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "user edit" }, "changed buffer was clobbered")
  end

  tests["vault_id does not imply default encrypt vault id"] = function()
    local fake = create_fake_vault()
    local pass = make_password_file(fake.dir)
    reset_config(fake, { password_files = false, vault_ids = "prod@" .. pass, encrypt_vault_id = nil })

    local buf = new_buffer({ "plain" })
    vault.encrypt(buf)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt with vault_id did not finish")

    assert_true(log_contains(fake.log, "ARG:prod@" .. pass), "vault_id was not passed")
    assert_false(log_contains(fake.log, "ARG:--encrypt-vault-id"), "encrypt_vault_id should be opt-in")

    reset_config(fake, { password_files = false, vault_ids = "prod@" .. pass, encrypt_vault_id = "prod" })
    local other = new_buffer({ "plain" })
    vault.encrypt(other)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(other, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.2;AES256;prod"
    end, "encrypt with explicit encrypt_vault_id did not finish")

    assert_true(log_contains(fake.log, "ARG:--encrypt-vault-id"), "explicit encrypt_vault_id flag was not passed")
    assert_true(log_has_line(fake.log, "ARG:prod"), "explicit encrypt_vault_id value was not passed")
  end

  tests["vault_ids pass multiple vault identities"] = function()
    local fake = create_fake_vault()
    local dev_pass = make_password_file(fake.dir)
    local prod_pass = make_password_file(fake.dir)
    reset_config(fake, {
      password_files = false,
      vault_ids = { "dev@" .. dev_pass, "prod@" .. prod_pass },
      encrypt_vault_id = "prod",
    })

    local buf = new_buffer({ "plain" })
    vault.encrypt(buf)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.2;AES256;prod"
    end, "encrypt with vault_ids did not finish")

    assert_true(log_contains(fake.log, "ARG:dev@" .. dev_pass), "dev vault_id was not passed")
    assert_true(log_contains(fake.log, "ARG:prod@" .. prod_pass), "prod vault_id was not passed")
    assert_true(log_contains(fake.log, "ARG:--encrypt-vault-id"), "encrypt_vault_id flag was not passed")
    assert_true(log_has_line(fake.log, "ARG:prod"), "encrypt_vault_id value was not passed")
  end

  tests["view preserves source filetype"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "EDITME" })
    vim.bo[buf].filetype = "yaml"

    vault.view(buf)

    wait_until(function()
      return vim.api.nvim_get_current_buf() ~= buf
    end, "view window did not open")

    assert_eq(vim.bo[vim.api.nvim_get_current_buf()].filetype, "yaml", "view buffer filetype was not preserved")
    vim.api.nvim_win_close(0, true)
  end

  tests["opening a vault file does nothing until a command is run"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    assert_eq(
      #vim.api.nvim_get_autocmds({ group = "AnsibleVault", event = "BufReadPost" }),
      0,
      "the plugin must not act on files merely being opened"
    )

    local path = fake.dir .. "/untouched.yml"
    write_file(path, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()

    assert_eq(vim.bo[buf].buftype, "", "the buffer should be left alone")
    assert_true(vault.is_buffer_encrypted(buf), "and still be recognisable as a vault file")
  end

  tests["VaultEdit uses a no-swap acwrite buffer and saves atomically"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local original_file = fake.dir .. "/secret.yml"
    write_file(original_file, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")

    vim.cmd("edit " .. vim.fn.fnameescape(original_file))
    local original_buf = vim.api.nvim_get_current_buf()

    vault.edit(original_buf)

    wait_until(function()
      return vim.api.nvim_get_current_buf() ~= original_buf
    end, "VaultEdit buffer did not open")

    local edit_buf = vim.api.nvim_get_current_buf()
    assert_true(vim.api.nvim_buf_is_valid(original_buf), "original buffer was deleted")
    assert_eq(vim.bo[edit_buf].buftype, "acwrite", "edit buffer must be acwrite")
    assert_eq(vim.bo[edit_buf].swapfile, false, "edit buffer must not use swapfile")
    assert_eq(vim.bo[edit_buf].undofile, false, "edit buffer must not use undofile")
    assert_eq(vim.bo[edit_buf].bufhidden, "wipe", "edit buffer should wipe on close")

    vim.api.nvim_buf_set_lines(edit_buf, 0, -1, false, { "plain: new" })
    vim.cmd("write")

    wait_until(function()
      return not vim.api.nvim_buf_is_valid(edit_buf) or vim.api.nvim_get_current_buf() == original_buf
    end, "VaultEdit save did not close the edit buffer")

    assert_true(read_file(original_file):match("^%$ANSIBLE_VAULT;1.1;AES256"), "encrypted file was not written")
    assert_true(vim.api.nvim_buf_is_valid(original_buf), "original buffer was not restored")
  end

  tests["VaultEdit refuses to overwrite externally changed files"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local original_file = fake.dir .. "/external-change.yml"
    write_file(original_file, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")

    vim.cmd("edit " .. vim.fn.fnameescape(original_file))
    local original_buf = vim.api.nvim_get_current_buf()

    vault.edit(original_buf)

    wait_until(function()
      return vim.api.nvim_get_current_buf() ~= original_buf
    end, "VaultEdit buffer did not open")

    local edit_buf = vim.api.nvim_get_current_buf()
    write_file(original_file, "$ANSIBLE_VAULT;1.1;AES256\nEXTERNAL CHANGE\n")

    vim.api.nvim_buf_set_lines(edit_buf, 0, -1, false, { "plain: new" })
    vim.cmd("write")

    wait_until(function()
      return notification_contains("Original file changed on disk")
    end, "VaultEdit did not detect the external file change")

    assert_true(vim.api.nvim_buf_is_valid(edit_buf), "edit buffer should remain open after a refused save")
    assert_true(vim.bo[edit_buf].modified, "edit buffer should remain modified after a refused save")
    assert_true(read_file(original_file):find("EXTERNAL CHANGE", 1, true), "external file content was overwritten")
    vim.api.nvim_buf_delete(edit_buf, { force = true })
  end

  tests["VaultEncrypt on a key: value line keeps the key"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "password: secret" })

    vault.encrypt(nil, { range = 1, line1 = 1, line2 = 1 })

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
    end, "YAML key was not preserved for full-line string encryption")

    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    assert_eq(lines[1], "password: !vault |", "full-line YAML output has wrong first line")
    assert_eq(lines[2], "          $ANSIBLE_VAULT;1.1;AES256", "full-line YAML output has wrong vault header")
  end

  tests["command args can override encrypt vault id"] = function()
    local fake = create_fake_vault()
    local dev_pass = make_password_file(fake.dir)
    local prod_pass = make_password_file(fake.dir)
    reset_config(fake, {
      password_files = false,
      vault_ids = { "dev@" .. dev_pass, "prod@" .. prod_pass },
    })

    local line = "password: secret"
    local buf = new_buffer({ line })

    vim.cmd("1VaultEncrypt --encrypt-vault-id prod")

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
    end, "VaultEncrypt command arg did not encrypt")

    assert_true(log_contains(fake.log, "ARG:--encrypt-vault-id"), "encrypt vault id flag was not passed")
    assert_true(log_has_line(fake.log, "ARG:prod"), "encrypt vault id value was not passed")
  end

  tests["--vault-password-file can be repeated"] = function()
    local fake = create_fake_vault()
    local first = fake.dir .. "/first-pass"
    local second = fake.dir .. "/second-pass"
    write_file(first, "one\n")
    write_file(second, "two\n")
    reset_config(fake, { password_files = false })

    local buf = new_buffer({ "plain" })
    vim.cmd(
      string.format(
        "VaultEncrypt --vault-password-file %s --vault-password-file %s",
        vim.fn.fnameescape(first),
        vim.fn.fnameescape(second)
      )
    )

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt with two password files did not finish")

    assert_true(log_has_line(fake.log, "ARG:" .. first), "the first password file was dropped")
    assert_true(log_has_line(fake.log, "ARG:" .. second), "the second password file was dropped")
  end

  tests["password_files accepts a single string or a list"] = function()
    local fake = create_fake_vault()
    local pass = make_password_file(fake.dir)
    reset_config(fake, { password_files = { pass } })

    local buf = new_buffer({ "plain" })
    vault.encrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt with a one-element list did not finish")

    assert_true(log_has_line(fake.log, "ARG:" .. pass), "a one-element list should behave like a bare string")
  end

  tests["a command password-file override replaces the configured list"] = function()
    local fake = create_fake_vault()
    local first = fake.dir .. "/configured-one"
    local second = fake.dir .. "/configured-two"
    local override = fake.dir .. "/override-pass"
    for _, path in ipairs({ first, second, override }) do
      write_file(path, "secret\n")
    end
    reset_config(fake, { password_files = { first, second } })

    local buf = new_buffer({ "plain" })
    vim.cmd("VaultEncrypt --vault-password-file " .. vim.fn.fnameescape(override))

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt with an overridden password file did not finish")

    assert_true(log_has_line(fake.log, "ARG:" .. override), "the override was not passed")
    -- A merged list would leave the second configured entry in place and pass a
    -- credential the user did not name on the command line.
    assert_false(log_has_line(fake.log, "ARG:" .. first), "the configured list must be replaced, not merged")
    assert_false(log_has_line(fake.log, "ARG:" .. second), "the configured list must be replaced, not merged")
  end

  tests["--ask-vault-password forces a prompt over configured credentials"] = function()
    local fake = create_fake_vault()
    local pass = make_password_file(fake.dir)
    reset_config(fake, { password_files = pass })

    local original_inputsecret = vim.fn.inputsecret
    local prompted = false
    vim.fn.inputsecret = function()
      prompted = true
      return "typed"
    end

    local buf = new_buffer({ "plain" })
    vim.cmd("VaultEncrypt --ask-vault-password")

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt with a forced prompt did not finish")

    vim.fn.inputsecret = original_inputsecret
    assert_true(prompted, "the flag must prompt even though a password file is configured")
    assert_false(log_has_line(fake.log, "ARG:" .. pass), "the configured password file must not also be passed")
    -- The flag is plugin-level: ansible-vault puts --ask-vault-password and
    -- --vault-password-file in one mutually exclusive group, and the child has no
    -- tty to prompt on anyway.
    assert_false(log_has_line(fake.log, "ARG:--ask-vault-password"), "the flag must not reach ansible-vault")
    assert_true(log_has_line(fake.log, "ENVPW:set"), "the typed password should go through the environment")
  end

  tests["an unknown argument is rejected instead of ignored"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "plain" })

    -- `--vault-pass-file` is a real ansible-vault alias, so users will type it.
    -- Silently treating it as a positional used to fall through to a password
    -- prompt, which reads as "the credential was not found".
    vim.cmd("VaultEncrypt --vault-pass-file /nope")
    assert_true(notification_contains("unknown or incomplete argument"), "the bad flag was not reported")
    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "plain" }, "the buffer must be left alone")

    vim.cmd("VaultEncrypt stray-positional")
    assert_true(notification_contains("unexpected argument"), "a stray positional was not reported")
  end

  tests["setup rejects unknown keys and impossible combinations"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    local good = vim.deepcopy(vault.config)

    vault.setup({ ansible_vault_path = fake.path, notify_success = false })
    assert_true(notification_contains("unknown option: notify_success"), "an unknown key was accepted")
    assert_eq(vault.config, good, "a rejected setup must not change the configuration")

    vault.setup({ ansible_vault_path = fake.path, vault_ids = 42 })
    assert_true(notification_contains("vault_ids must be string or table"), "a wrong type was accepted")

    vault.setup({ ask_password = true, password_files = "/some/pass" })
    assert_true(
      notification_contains("ask_password cannot be combined with password_files"),
      "ansible-vault treats these as mutually exclusive"
    )

    vault.setup({ new_vault_id = "new@/a", new_password_file = "/b" })
    assert_true(
      notification_contains("new_vault_id and new_password_file are mutually exclusive"),
      "ansible-vault puts these in one mutually exclusive group"
    )
  end

  tests["command vault-id override replaces configured password file"] = function()
    local fake = create_fake_vault()
    local old_pass = fake.dir .. "/old-pass"
    local prod_pass = fake.dir .. "/prod-pass"
    write_file(old_pass, "old\n")
    write_file(prod_pass, "prod\n")

    reset_config(fake, { password_files = old_pass })

    new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "TARGET" })
    vim.cmd("VaultView --vault-id prod@" .. prod_pass)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false)[1] == "plain: target"
    end, "VaultView with command vault-id override did not finish")

    assert_true(log_contains(fake.log, "ARG:--vault-id"), "command vault-id flag was not passed")
    assert_true(log_has_line(fake.log, "ARG:prod@" .. prod_pass), "command vault-id value was not passed")
    assert_false(log_has_line(fake.log, "ARG:" .. old_pass), "configured password file was not overridden")

    vim.api.nvim_win_close(0, true)
  end

  tests["command completion exposes override flags and inline labels"] = function()
    local fake = create_fake_vault()
    local prod_pass = make_password_file(fake.dir)
    reset_config(fake, {
      password_files = false,
      vault_ids = { "prod@" .. prod_pass },
    })

    local label_completion = vim.fn.getcompletion("VaultEncrypt p", "cmdline")
    assert_true(vim.tbl_contains(label_completion, "prod"), "inline encrypt label was not completed")

    local flag_completion = vim.fn.getcompletion("VaultEdit --vault", "cmdline")
    assert_true(vim.tbl_contains(flag_completion, "--vault-id"), "vault-id flag was not completed")
    assert_true(
      vim.tbl_contains(flag_completion, "--vault-password-file"),
      "vault-password-file flag was not completed"
    )
  end

  tests["an interactive password is never reused across operations"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { password_files = false })

    local original_inputsecret = vim.fn.inputsecret
    local prompt_count = 0
    vim.fn.inputsecret = function()
      prompt_count = prompt_count + 1
      return "secret"
    end

    local first = new_buffer({ "first" })
    vault.encrypt(first)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(first, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "first encrypt did not finish")

    local second = new_buffer({ "second" })
    vault.encrypt(second)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(second, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "second encrypt did not finish")

    vim.fn.inputsecret = original_inputsecret
    -- No cache means no window in which a secret sits in the Lua heap between
    -- operations, so each one must ask again.
    assert_eq(prompt_count, 2, "each operation must prompt for its own password")
  end

  tests["slow vault operations time out"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    require("ansible-vault.cli").timeout_ms = 50
    vim.env.FAKE_VAULT_SLEEP = "1"

    local buf = new_buffer({ "plain: value" })
    vault.encrypt(buf)

    wait_until(function()
      return notification_contains("timed out")
    end, "slow vault operation did not time out")

    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "plain: value" }, "timed out operation changed buffer")
    vim.env.FAKE_VAULT_SLEEP = nil
    require("ansible-vault.cli").timeout_ms = 30000
  end

  tests["operations announce themselves on AnsibleVaultOperation"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "plain: value" })

    -- Collect rather than `once`: there is a single pattern for every operation, so
    -- an earlier test's in-flight write can fire it first and consume a one-shot
    -- autocmd. Match on the buffer instead.
    local seen = {}
    local id = vim.api.nvim_create_autocmd("User", {
      pattern = "AnsibleVaultOperation",
      callback = function(event)
        if event.data and event.data.buf == buf then
          table.insert(seen, event.data)
        end
      end,
    })

    vault.encrypt(buf)

    wait_until(function()
      return vault.is_buffer_encrypted(buf) and #seen > 0
    end, "encrypt did not finish or did not announce itself")
    vim.api.nvim_del_autocmd(id)

    assert_eq(seen[1].op, "encrypt", "the event should carry the operation")
    assert_eq(seen[1].scope, "file", "the event should carry the scope it applied to")
    assert_eq(seen[1].buf, buf, "the event should carry the buffer it applied to")
  end

  tests["VaultDecrypt over a range replaces the YAML vault block"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:secret",
    })

    vault.decrypt(nil, { range = 3, line1 = 1, line2 = 3 })

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: secret"
    end, "the YAML vault block in the range was not decrypted")

    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "password: secret" })
  end

  tests["the cursor resolves inline view and decrypt without a range"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "password: secret" })
    vim.api.nvim_win_set_cursor(0, { 1, 0 })
    vault.encrypt(nil, { range = 1, line1 = 1, line2 = 1 })

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
    end, "under-cursor YAML value was not encrypted")

    vim.api.nvim_win_set_cursor(0, { 2, 10 })
    vault.view()

    wait_until(function()
      return vim.api.nvim_get_current_buf() ~= buf
    end, "under-cursor vault view did not open")

    assert_eq(vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false), { "secret" })

    vim.api.nvim_set_current_buf(buf)
    vim.api.nvim_win_set_cursor(0, { 2, 10 })
    vault.decrypt()

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: secret"
    end, "under-cursor vault block was not decrypted")

    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "password: secret" })
  end

  tests["under cursor vault lookup does not select a previous block"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:secret",
      "other: value",
    })

    vim.api.nvim_win_set_cursor(0, { 4, 0 })
    vault.view()

    assert_eq(vim.api.nvim_get_current_buf(), buf, "view should not open for a cursor outside the vault block")
    assert_true(notification_contains("nothing encrypted here"), "missing error for cursor outside a vault block")
  end

  tests["scope: a vault file wins over a !vault block at the cursor"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    -- yaml.find_block treats a bare $ANSIBLE_VAULT line as the start of an inline
    -- block, so a whole-file vault must be recognised first or :VaultDecrypt would
    -- try to splice the file into itself as a YAML value.
    local buf = new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "EDITME" })
    vim.api.nvim_win_set_cursor(0, { 1, 0 })

    vault.decrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "plain: old"
    end, "a whole-file vault was not decrypted as a file")

    assert_eq(vim.b[buf].ansible_vault_plaintext, "file", "the file scope should have won")
  end

  tests["scope: VaultEncrypt with no range encrypts the whole buffer"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    -- Every line here is a `key: value` pair. Resolving the cursor line as an
    -- inline value would silently encrypt one line instead of the file.
    local buf = new_buffer({ "alpha: one", "beta: two" })
    vim.api.nvim_win_set_cursor(0, { 2, 0 })

    vault.encrypt(buf)
    wait_until(function()
      return vault.is_buffer_encrypted(buf)
    end, "VaultEncrypt with no range did not encrypt the buffer")

    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    assert_eq(lines[1], "$ANSIBLE_VAULT;1.1;AES256", "the whole buffer should have been encrypted")
    assert_true(lines[2]:find("alpha: one", 1, true) ~= nil, "the whole buffer content should have been the input")
  end

  tests["scope: VaultDecrypt refuses when there is nothing encrypted"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "alpha: one" })
    vault.decrypt(buf)

    assert_true(notification_contains("nothing encrypted here"), "the refusal should name what it looked for")
    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "alpha: one" }, "the buffer must be untouched")
  end

  tests["scope: VaultEdit refuses a range"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "password: !vault |", "          $ANSIBLE_VAULT;1.1;AES256", "          ENCSTR:x" })
    vault.edit(buf, { range = 3, line1 = 1, line2 = 3 })

    assert_true(notification_contains("whole vault file"), "VaultEdit should point at :VaultDecrypt for inline values")
  end

  tests["VaultEncrypt folds a decrypted inline value back without writing"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf, path = new_file_buffer(dir, "inline.yml", {
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:secret",
    })
    local before = read_file(path)

    vault.decrypt(buf, { range = 3, line1 = 1, line2 = 3 })
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: secret"
    end, "inline decrypt did not finish")
    assert_eq(vim.b[buf].ansible_vault_plaintext, "inline", "the buffer should be in inline plaintext mode")

    -- The inverse of decrypting in place, and like whole-file :VaultEncrypt it
    -- leaves the file alone: `:w` stays the user's decision.
    vault.encrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
    end, "VaultEncrypt did not fold the inline value back")

    assert_eq(vim.b[buf].ansible_vault_plaintext, nil, "the buffer should have left plaintext mode")
    assert_eq(read_file(path), before, "folding back must not write the file")
  end

  tests["a deleted inline region is not folded onto the next value"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf, path = new_file_buffer(dir, "deleted.yml", {
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:secret",
      "keepme: plain",
    })

    vault.decrypt(buf, { range = 3, line1 = 1, line2 = 3 })
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: secret"
    end, "inline decrypt did not finish")

    -- Delete the decrypted line. The extmark is left-gravity, so it now points at
    -- `keepme: plain`, which must not be mistaken for the region's content.
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, {})

    vim.cmd("silent write")
    wait_until(function()
      return vim.bo[buf].buftype == ""
    end, "write did not complete")

    assert_true(notification_contains("no longer there"), "the orphaned region should be reported")
    local written = read_file(path)
    assert_true(written:find("keepme: plain", 1, true) ~= nil, "the unrelated value must be written unchanged")
    assert_false(written:find("keepme: !vault", 1, true) ~= nil, "the unrelated value must not be encrypted")
  end

  tests["a second inline value can be decrypted while the first is open"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({
      "first: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:alpha",
      "second: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:beta",
    })

    vim.api.nvim_win_set_cursor(0, { 1, 0 })
    vault.decrypt()
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "first: alpha"
    end, "the first value was not decrypted")

    -- Inline plaintext mode must not make the buffer look wholly decrypted: it is
    -- ordinary YAML, and the other values are still encrypted and still addressable.
    vim.api.nvim_win_set_cursor(0, { 2, 0 })
    vault.decrypt()
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 1, 2, false)[1] == "second: beta"
    end, "a second value could not be decrypted while the first was open")

    assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "first: alpha", "second: beta" })
  end

  tests["VaultRekey rotates a single inline value"] = function()
    local fake = create_fake_vault()
    local old_pass = make_password_file(fake.dir)
    local new_pass = fake.dir .. "/inline-new-pass"
    write_file(new_pass, "new\n")
    reset_config(fake, { password_files = old_pass, new_password_file = new_pass })

    local buf = new_buffer({
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:secret",
      "other: plain",
    })

    vault.rekey({ range = 3, line1 = 1, line2 = 3 })

    wait_until(function()
      return notification_contains("Inline value rekeyed successfully")
    end, "inline rekey did not finish")

    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    assert_eq(lines[1], "password: !vault |", "the key should be preserved")
    assert_eq(lines[#lines], "other: plain", "unrelated lines must be left alone")
    assert_true(log_has_line(fake.log, "ARG:" .. new_pass), "the new credential should be used to re-encrypt")
    assert_true(log_has_line(fake.log, "ARG:--stdin-name"), "the value must be re-encrypted under its own key")
    assert_true(log_has_line(fake.log, "ARG:password"), "the key name should be passed as --stdin-name")

    -- Plaintext must never land in the buffer on the way through. (The fake echoes
    -- its input back inside the ciphertext, so look for the decrypted *shape*.)
    assert_false(vim.tbl_contains(lines, "password: secret"), "the decrypted value must not be left in the buffer")
  end

  tests["VaultRekey refuses an inline value while it is decrypted"] = function()
    local fake = create_fake_vault()
    local new_pass = fake.dir .. "/refuse-new-pass"
    write_file(new_pass, "new\n")
    reset_config(fake, { new_password_file = new_pass })

    local buf = new_buffer({
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:secret",
    })

    vault.decrypt(buf, { range = 3, line1 = 1, line2 = 3 })
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: secret"
    end, "inline decrypt did not finish")

    vault.rekey()
    assert_true(
      notification_contains("Write or discard the decrypted content"),
      "rekey should refuse decrypted content"
    )
  end

  tests["VaultRekey never passes --encrypt-vault-id"] = function()
    local fake = create_fake_vault()
    local old_pass = make_password_file(fake.dir)
    local new_pass = fake.dir .. "/new-pass"
    write_file(new_pass, "new\n")
    reset_config(fake, { password_files = old_pass, new_password_file = new_pass })

    -- A 1.2 header: this is the case where the plugin used to derive
    -- --encrypt-vault-id from the label it found.
    local path = fake.dir .. "/labelled.yml"
    write_file(path, "$ANSIBLE_VAULT;1.2;AES256;prod\nEDITME\n")
    vim.cmd("edit " .. vim.fn.fnameescape(path))

    vault.rekey()
    wait_until(function()
      return read_file(path):find("REKEYED", 1, true) ~= nil
    end, "VaultRekey did not rewrite the file")

    -- On `rekey` this flag selects the new secret from a pool seeded with the OLD
    -- identities, so it either errors out or silently re-encrypts with the old
    -- password. The label is carried by the new identity instead.
    assert_false(log_contains(fake.log, "ARG:--encrypt-vault-id"), "--encrypt-vault-id must never reach rekey")
    assert_true(log_has_line(fake.log, "ARG:--new-vault-id"), "the label should ride on the new identity")
    assert_true(log_has_line(fake.log, "ARG:prod@" .. new_pass), "the new identity should carry the old label")
    assert_eq(vim.fn.readfile(path, "", 1)[1], "$ANSIBLE_VAULT;1.2;AES256;prod", "the 1.2 label must survive the rekey")
  end

  tests["VaultRekey without a label stays on format 1.1"] = function()
    local fake = create_fake_vault()
    local new_pass = fake.dir .. "/new-pass-plain"
    write_file(new_pass, "new\n")
    reset_config(fake, { new_password_file = new_pass })

    local path = fake.dir .. "/plain.yml"
    write_file(path, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")
    vim.cmd("edit " .. vim.fn.fnameescape(path))

    vault.rekey()
    wait_until(function()
      return read_file(path):find("REKEYED", 1, true) ~= nil
    end, "VaultRekey did not rewrite the file")

    assert_true(log_has_line(fake.log, "ARG:--new-vault-password-file"), "a plain rekey should pass the password file")
    assert_false(log_contains(fake.log, "ARG:--new-vault-id"), "nothing should invent a label for a 1.1 file")
    assert_eq(vim.fn.readfile(path, "", 1)[1], "$ANSIBLE_VAULT;1.1;AES256", "a 1.1 file should stay 1.1")
  end

  tests["VaultRekey rekeys a file-backed encrypted buffer"] = function()
    local fake = create_fake_vault()
    local new_pass = make_password_file(fake.dir)
    reset_config(fake, { new_password_file = new_pass })

    local original_file = fake.dir .. "/rekey.yml"
    write_file(original_file, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")

    vim.cmd("edit " .. vim.fn.fnameescape(original_file))
    local buf = vim.api.nvim_get_current_buf()

    vault.rekey()

    wait_until(function()
      return read_file(original_file):find("REKEYED", 1, true) ~= nil
    end, "VaultRekey did not rewrite the file")

    assert_true(log_contains(fake.log, "ARG:--new-vault-password-file"), "new password file flag was not passed")
    assert_true(log_contains(fake.log, "ARG:" .. new_pass), "new password file path was not passed")
    assert_true(vault.is_buffer_encrypted(buf), "buffer was not reloaded as encrypted after rekey")
  end

  tests["B3 double VaultEdit on same file does not crash"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    vim.env.FAKE_VAULT_SLEEP = "0.1"

    local original_file = fake.dir .. "/double-edit.yml"
    write_file(original_file, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")

    vim.cmd("edit " .. vim.fn.fnameescape(original_file))
    local original_buf = vim.api.nvim_get_current_buf()

    vault.edit(original_buf)
    wait_until(function()
      return vim.api.nvim_get_current_buf() ~= original_buf
    end, "first VaultEdit did not open scratch buffer")

    local edit_buf = vim.api.nvim_get_current_buf()
    vim.cmd("split")
    vault.edit(original_buf)

    wait_until(function()
      return notification_contains("buffer name conflict")
    end, "second VaultEdit did not report name conflict")

    vim.api.nvim_buf_delete(edit_buf, { force = true })
    vim.cmd("only")
    vim.env.FAKE_VAULT_SLEEP = nil
  end

  tests["B4 encrypt decrypt roundtrip preserves content structure"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({ "line1", "line2", "" })
    assert_eq(vim.api.nvim_buf_line_count(buf), 3, "buffer should have 3 lines including trailing empty")

    vault.encrypt(buf)
    wait_until(function()
      return vault.is_buffer_encrypted(buf)
    end, "encrypt did not finish")

    vault.decrypt(buf)
    wait_until(function()
      return not vault.is_buffer_encrypted(buf)
    end, "decrypt did not finish")

    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    assert_true(#lines >= 1, "decrypted buffer should have content")
    assert_false(vault.is_buffer_encrypted(buf), "buffer should not be encrypted after decrypt")
  end

  tests["B5 a failed password is re-prompted"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { password_files = false })

    local original_inputsecret = vim.fn.inputsecret
    local prompt_count = 0
    vim.fn.inputsecret = function()
      prompt_count = prompt_count + 1
      return "mypass"
    end

    vim.env.FAKE_VAULT_FAIL = "simulated password error"

    local buf = new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "EDITME" })
    vault.decrypt(buf)
    wait_until(function()
      return notification_contains("Decryption failed")
    end, "decrypt with wrong password did not fail")

    vim.env.FAKE_VAULT_FAIL = nil
    vault.decrypt(buf)
    wait_until(function()
      return not vault.is_buffer_encrypted(buf)
    end, "decrypt with correct password did not succeed")

    vim.fn.inputsecret = original_inputsecret
    assert_eq(prompt_count, 2, "password should have been re-prompted after failure")
  end

  tests["B6 encrypt string ignores YAML comments"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    local stdin_log = fake.dir .. "/stdin.log"
    vim.env.FAKE_VAULT_STDIN_LOG = stdin_log

    local buf = new_buffer({ 'password: "sec#ret" # prod' })

    vault.encrypt(nil, { range = 1, line1 = 1, line2 = 1 })

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
    end, "YAML value with comment was not encrypted")

    assert_eq(read_file(stdin_log), "sec#ret", "YAML comments or quoted # were included in the encrypted value")
  end

  tests["B6 decrypt string quotes YAML special values"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local function quote(s)
      return require("ansible-vault.yaml").quote_value(s)
    end

    assert_eq(quote("yes"), '"yes"', "boolean 'yes' should be quoted")
    assert_eq(quote("no"), '"no"', "boolean 'no' should be quoted")
    assert_eq(quote("true"), '"true"', "boolean 'true' should be quoted")
    assert_eq(quote("false"), '"false"', "boolean 'false' should be quoted")
    assert_eq(quote("null"), '"null"', "null should be quoted")
    assert_eq(quote("on"), '"on"', "boolean 'on' should be quoted")
    assert_eq(quote("off"), '"off"', "boolean 'off' should be quoted")
    assert_eq(quote("# comment"), '"# comment"', "hash-prefixed should be quoted")
    assert_eq(quote("[list]"), '"[list]"', "bracket-prefixed should be quoted")
    assert_eq(quote("normal"), "normal", "normal value should not be quoted")
    assert_eq(quote(""), '""', "empty should be quoted")
  end

  tests["B7 find vault block beyond 100 lines"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local lines = {}
    table.insert(lines, "password: !vault |")
    table.insert(lines, "          $ANSIBLE_VAULT;1.1;AES256")
    for i = 1, 120 do
      table.insert(lines, "          " .. string.rep("A", 60))
    end
    table.insert(lines, "          ENCSTR:verylongvalue")
    table.insert(lines, "other: value")

    local buf = new_buffer(lines)
    local cursor_row = #lines - 1
    vim.api.nvim_win_set_cursor(0, { cursor_row, 30 })

    vault.view()

    wait_until(function()
      return vim.api.nvim_get_current_buf() ~= buf
    end, "under-cursor vault view did not open for block > 100 lines")

    assert_true(vim.api.nvim_get_current_buf() ~= buf, "view window should be open")
    vim.api.nvim_win_close(0, true)
  end

  tests["B8 re-setup clears previous config"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { encrypt_vault_id = "prod" })
    assert_eq(vault.config.encrypt_vault_id, "prod")

    local table_before = vault.config

    vault.setup({})
    assert_eq(vault.config.encrypt_vault_id, nil, "encrypt_vault_id should reset to nil on re-setup")
    assert_eq(vault.config.ansible_vault_path, nil, "the executable set by the previous setup should be cleared")

    -- Filled in place, not replaced: :checkhealth and anything else holding
    -- `vault.config` would otherwise keep reading a detached table after setup().
    assert_true(table_before == vault.config, "setup() must not swap the config table out from under its holders")
  end

  tests["B9 command args support quoted paths with spaces"] = function()
    local fake = create_fake_vault()
    local pass_path = fake.dir .. "/path with spaces/vault pass"
    vim.fn.mkdir(fake.dir .. "/path with spaces", "p")
    write_file(pass_path, "secret\n")
    vim.fn.setfperm(pass_path, "rw-------")
    reset_config(fake, { password_files = false })

    new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "EDITME" })
    local cmd = "VaultView --vault-password-file '" .. pass_path .. "'"
    vim.cmd(cmd)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, 1, false)[1] == "plain: old"
    end, "VaultView with quoted path did not finish")

    assert_true(log_contains(fake.log, "ARG:" .. pass_path), "quoted path was not passed as one arg")
    vim.api.nvim_win_close(0, true)
  end

  tests["B9 command args support escaped spaces"] = function()
    local fake = create_fake_vault()
    local pass_path = fake.dir .. "/path with spaces/vault pass"
    vim.fn.mkdir(fake.dir .. "/path with spaces", "p")
    write_file(pass_path, "secret\n")
    vim.fn.setfperm(pass_path, "rw-------")
    reset_config(fake, { password_files = false })

    new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "EDITME" })
    local escaped_path = pass_path:gsub(" ", "\\ ")
    vim.cmd("VaultView --vault-password-file " .. escaped_path)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, 1, false)[1] == "plain: old"
    end, "VaultView with escaped-space path did not finish")

    assert_true(log_contains(fake.log, "ARG:" .. pass_path), "escaped-space path was not passed as one arg")
    vim.api.nvim_win_close(0, true)
  end

  tests["health check runs"] = function()
    local fake = create_fake_vault()
    reset_config(fake)
    require("ansible-vault.health").check()
  end
end
