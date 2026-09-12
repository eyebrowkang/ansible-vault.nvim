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
  local make_project = H.make_project
  local new_file_buffer = H.new_file_buffer
  local new_buffer = H.new_buffer
  local log_contains = H.log_contains
  local log_has_line = H.log_has_line
  local notification_contains = H.notification_contains
  --- Inline YAML shapes ------------------------------------------------------

  tests["inline parser handles every shape ansible accepts"] = function()
    local parse = require("ansible-vault.yaml").parse_block
    local body = "          $ANSIBLE_VAULT;1.2;AES256;prod\n          6162636465"

    local cases = {
      { "canonical", "password: !vault |\n" .. body, "password" },
      { "chomping indicator", "password: !vault |-\n" .. body, "password" },
      { "folded scalar", "password: !vault >\n" .. body, "password" },
      { "indent indicator", "password: !vault |2-\n" .. body, "password" },
      { "trailing comment", "password: !vault | # note\n" .. body, "password" },
      { "double quoted key", '"password": !vault |\n' .. body, "password" },
      { "single quoted key", "'password': !vault |\n" .. body, "password" },
      { "list item", "- password: !vault |\n" .. body, "password" },
      { "nested key", "    password: !vault |\n" .. body, "password" },
      { "bare list item", "- !vault |\n" .. body, nil },
    }

    for _, case in ipairs(cases) do
      local parsed = parse(case[2])
      assert_true(parsed ~= nil, case[1] .. ": failed to parse")
      assert_eq(parsed.var_name, case[3], case[1] .. ": wrong key")
      assert_eq(
        parsed.vault_content,
        "$ANSIBLE_VAULT;1.2;AES256;prod\n6162636465",
        case[1] .. ": ciphertext was not extracted cleanly"
      )
      assert_eq(parsed.header.label, "prod", case[1] .. ": vault id label was not read")
    end

    assert_true(parse("password: hunter2") == nil, "plain values must not parse as vault blocks")
    assert_true(parse("password: !vault |") == nil, "a header with no ciphertext must not parse")
  end

  tests["inline parser strips carriage returns"] = function()
    local parse = require("ansible-vault.yaml").parse_block
    local parsed = parse("password: !vault |\r\n          $ANSIBLE_VAULT;1.1;AES256\r\n          6162\r")
    assert_true(parsed ~= nil, "CRLF block did not parse")
    assert_eq(parsed.vault_content, "$ANSIBLE_VAULT;1.1;AES256\n6162", "carriage returns must not reach ansible-vault")
  end

  tests["header parser reads version and vault id label"] = function()
    local header = vault.parse_header("$ANSIBLE_VAULT;1.2;AES256;prod")
    assert_eq(header.version, "1.2")
    assert_eq(header.cipher, "AES256")
    assert_eq(header.label, "prod")

    assert_eq(vault.parse_header("$ANSIBLE_VAULT;1.1;AES256").label, nil)
    assert_eq(vault.parse_header("          $ANSIBLE_VAULT;1.2;AES256;dev").label, "dev")
    assert_true(vault.parse_header("not a header") == nil)
    assert_true(vault.parse_header("$ANSIBLE_VAULT;x;AES256") == nil)
  end

  tests["a trailing blank line is not swallowed by an inline block"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local buf = new_buffer({
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          ENCSTR:hunter2",
      "",
      "other: value",
    })

    vim.api.nvim_win_set_cursor(0, { 2, 0 })
    vault.decrypt()

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: hunter2"
    end, "inline value was not decrypted")

    assert_eq(
      vim.api.nvim_buf_get_lines(buf, 0, -1, false),
      { "password: hunter2", "", "other: value" },
      "lines after the block must be left alone"
    )
  end

  --- Vault id labels ---------------------------------------------------------

  tests["a 1.2 vault id label survives re-encryption"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local buf = new_file_buffer(dir, "vault.yml", { "$ANSIBLE_VAULT;1.2;AES256;prod", "ENC:plain" })

    -- Any operation records the header label before decrypting.
    vault.decrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "plain: value"
    end, "buffer was not decrypted")

    assert_eq(vim.b[buf].ansible_vault_label, "prod", "the vault id label should be remembered")

    vault.encrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] ~= "plain: value"
    end, "buffer was not re-encrypted")

    assert_eq(
      vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1],
      "$ANSIBLE_VAULT;1.2;AES256;prod",
      "re-encrypting must not downgrade the file to 1.1 and drop its label"
    )
  end

  --- ansible.cfg and ANSIBLE_* ----------------------------------------------

  tests["ansible.cfg found upward supplies credentials without extra flags"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { password_files = false })

    local root = make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    local buf = new_file_buffer(root .. "/group_vars/prod", "vault.yml", { "plain" })

    vault.encrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt using ansible.cfg credentials did not finish")

    -- Passing our own flag on top of ansible.cfg is what makes ansible-vault fail
    -- with "The vault-ids default,default are available to encrypt".
    assert_false(log_contains(fake.log, "ARG:--vault-password-file"), "no credential flag should be passed")
    assert_false(log_contains(fake.log, "ARG:--vault-id"), "no credential flag should be passed")
    assert_true(log_has_line(fake.log, "CWD:" .. root), "ansible-vault must run where the config was found")

    local described =
      require("ansible-vault.credentials").describe(vault.config, { file_path = vim.api.nvim_buf_get_name(buf) })
    assert_eq(described.cfg_path, root .. "/ansible.cfg", "the discovered config should be reported")
    assert_eq(described.source, "ansible.cfg", "credentials should be attributed to ansible.cfg")
  end

  tests["configured credentials name an identity when ansible.cfg adds one"] = function()
    local fake = create_fake_vault()
    local root = make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    local own_pass = make_password_file(fake.dir)
    reset_config(fake, { password_files = own_pass })

    local buf = new_file_buffer(root .. "/group_vars/prod", "vault.yml", { "plain" })

    vault.encrypt(buf)
    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt did not finish")

    assert_true(log_contains(fake.log, "ARG:" .. own_pass), "the configured password file should still win")
    assert_true(
      log_has_line(fake.log, "ARG:--encrypt-vault-id"),
      "the identity must be named explicitly, or ansible-vault refuses to choose"
    )
    assert_true(log_has_line(fake.log, "ARG:default"), "the plugin's own identity should be the one named")
  end

  tests["ANSIBLE_VAULT_PASSWORD_FILE is honoured and outranks ansible.cfg"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { password_files = false })

    local root = make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    local env_pass = make_password_file(fake.dir)
    vim.env.ANSIBLE_VAULT_PASSWORD_FILE = env_pass

    local buf = new_file_buffer(root .. "/group_vars/prod", "vault.yml", { "plain" })
    local described =
      require("ansible-vault.credentials").describe(vault.config, { file_path = vim.api.nvim_buf_get_name(buf) })
    assert_true(
      described.source:find("ANSIBLE_* environment", 1, true) ~= nil,
      "credentials should be attributed to the environment"
    )

    vim.env.ANSIBLE_VAULT_PASSWORD_FILE = nil
  end

  tests["ansible.cfg relative paths resolve against the config directory"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { password_files = false })

    local root = make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    local cfg = require("ansible-vault.ansible_cfg")
    cfg.clear_cache()

    local resolved = cfg.resolve(root .. "/group_vars/prod/vault.yml")
    assert_eq(resolved.settings.vault_password_file, root .. "/.vault_pass")
    assert_eq(resolved.cwd, root)
    assert_true(resolved.has_credentials)
  end

  --- Credential precedence ---------------------------------------------------

  tests["a command vault-id override replaces the configured list"] = function()
    local fake = create_fake_vault()
    local dev = make_password_file(fake.dir)
    local prod = make_password_file(fake.dir)
    reset_config(fake, { password_files = false, vault_ids = { "dev@" .. dev, "prod@" .. prod } })

    local buf = new_buffer({ "plain" })
    vim.cmd("VaultEncrypt --vault-id only@" .. vim.fn.fnameescape(dev))

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] ~= "plain"
    end, "encrypt with an overridden vault id did not finish")

    assert_true(log_has_line(fake.log, "ARG:only@" .. dev), "the override should be used")
    assert_false(log_has_line(fake.log, "ARG:prod@" .. prod), "configured entries must not survive the override")
  end

  tests["interactive passwords never reach the filesystem"] = function()
    local fake = create_fake_vault()
    reset_config(fake, { password_files = false })

    local original = vim.fn.inputsecret
    vim.fn.inputsecret = function()
      return "typed-secret"
    end

    local buf = new_buffer({ "plain" })
    vault.encrypt(buf)

    wait_until(function()
      return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
    end, "encrypt with an interactive password did not finish")

    vim.fn.inputsecret = original

    assert_true(log_has_line(fake.log, "ENVPW:set"), "the password should be passed through the environment")

    local password_file
    for line in read_file(fake.log):gmatch("[^\n]+") do
      local candidate = line:match("^ARG:(/.+)$")
      if candidate and candidate:match("askpass") then
        password_file = candidate
      end
    end

    assert_true(password_file ~= nil, "a helper script should be passed as the password file")
    assert_false(read_file(password_file):find("typed-secret", 1, true) ~= nil, "the helper must contain no secret")
  end

  --- VaultCreate -------------------------------------------------------------

  tests["VaultCreate opens a protected buffer and writes ciphertext"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local path = dir .. "/new-vault.yml"

    vim.cmd("VaultCreate " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()

    assert_eq(vim.api.nvim_buf_get_name(buf), path, "the new buffer should be named after the target file")
    assert_false(vim.bo[buf].swapfile, "a new vault buffer must not use a swap file")
    assert_eq(vim.bo[buf].buftype, "acwrite", "writes must be routed through the plugin")
    assert_eq(vim.fn.filereadable(path), 0, "the file should not exist until it is written")

    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "secret: value" })
    vim.cmd("silent write")

    wait_until(function()
      return vim.fn.filereadable(path) == 1
    end, "VaultCreate write did not produce a file")

    assert_true(read_file(path):match("^%$ANSIBLE_VAULT"), "VaultCreate must write ciphertext")
  end

  tests["VaultCreate refuses to clobber an existing file"] = function()
    local fake = create_fake_vault()
    reset_config(fake)

    local dir = temp_dir()
    local path = dir .. "/exists.yml"
    write_file(path, "keep me\n")

    vim.cmd("VaultCreate " .. vim.fn.fnameescape(path))

    assert_true(notification_contains("File already exists"), "existing files must not be silently replaced")
    assert_eq(read_file(path), "keep me\n", "the existing file must be untouched")
  end
end
