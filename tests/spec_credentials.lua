---Configuration, command arguments and credential resolution.
---
---Where a claim is about the argv and environment the child is given, it is
---asserted against `credentials.resolve` directly rather than against what the
---process double happened to do with them: the double is byte-exact but is
---deliberately not an authority on Ansible's own precedence.
---@param H table
---@param tests table
return function(H, tests)
  local eq, yes, no = H.assert_eq, H.assert_true, H.assert_false

  local config = require("ansible-vault.config")
  local credentials = require("ansible-vault.credentials")

  --- The configuration surface ---------------------------------------------

  tests["only the four persistent options are accepted"] = function()
    eq(
      config.validate({
        vault_ids = { "prod@/p" },
        password_files = "/p",
        encrypt_vault_id = "prod",
        ansible_vault_path = "/bin/true",
      }),
      {}
    )
    eq(config.validate({ vault_ids = "prod@/p" }), {}, "a single string stands in for a one-element list")

    -- Operation-only settings describe a moment, not a preference. Silently
    -- ignoring them in setup() would leave the user believing every operation
    -- prompts, or that a rekey target is configured.
    for _, key in ipairs({ "ask_password", "new_vault_id", "new_password_file" }) do
      eq(config.validate({ [key] = "x" }), { "unknown option: " .. key }, key .. " must be rejected by setup")
    end
    eq(config.validate({ typo = 1 }), { "unknown option: typo" })
    eq(config.validate({ encrypt_vault_id = 1 }), { "encrypt_vault_id must be string, got number" })
    eq(config.validate({ password_files = 1 }), { "password_files must be string or table, got number" })
    eq(#config.validate({ typo = 1, encrypt_vault_id = 2 }), 2, "every problem should be reported at once")
  end

  tests["setup reports a bad option and changes nothing"] = function()
    local fake = H.create_fake_vault()
    local applied = H.reset_config(fake)
    H.clear_notifications()
    require("ansible-vault").setup({ ask_password = true })
    yes(H.notification_contains("unknown option: ask_password"))
    eq(config.values.password_files, applied.password_files, "a rejected setup must not replace the configuration")
  end

  tests["a later setup replaces list values instead of merging them"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false, vault_ids = { "a@/1", "b@/2" } })
    require("ansible-vault").setup({ ansible_vault_path = fake.path, vault_ids = { "c@/3" } })
    eq(config.values.vault_ids, { "c@/3" }, "element-wise merging would keep a credential the user removed")
    eq(config.values.password_files, nil)
  end

  tests["operation overrides replace configured credential lists"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false, vault_ids = { "dev@/1", "prod@/2" } })
    local effective = config.effective({ overrides = { vault_ids = { "only@/3" } } })
    eq(effective.vault_ids, { "only@/3" }, "naming one credential must not leave the others in place")
    eq(config.values.vault_ids, { "dev@/1", "prod@/2" }, "an operation must not write back to the configuration")

    -- `false` is the "explicitly unset" sentinel a command argument uses.
    eq(credentials.as_list(config.effective({ overrides = { vault_ids = false } }).vault_ids), {})
  end

  --- Command arguments ----------------------------------------------------

  local arg_errors = {
    { "VaultEncrypt --vault-password-file", "missing value for --vault-password-file" },
    { "VaultEncrypt --vault-id", "missing value for --vault-id" },
    { "VaultEncrypt --vault-id --encrypt-vault-id", "missing value for --vault-id" },
    { "VaultEncrypt --bogus", "unknown argument: --bogus" },
    { "VaultEncrypt --ask-vault-password --vault-id x@/y", "cannot be combined" },
    { "VaultEncrypt --vault-password-file /y --ask-vault-password", "cannot be combined" },
    { "VaultRekey --new-vault-id a@/b --new-vault-password-file /c", "mutually exclusive" },
    { "VaultEncrypt --new-vault-id a@/b", "unknown argument: --new-vault-id" },
    { "VaultDecrypt --encrypt-vault-id prod", "unknown argument: --encrypt-vault-id" },
    -- The one that matters most: on `rekey` this flag seeds the NEW secret pool
    -- with the OLD identities, so accepting it would let a rekey report success
    -- and leave the file on its old password.
    { "VaultRekey --encrypt-vault-id prod", "unknown argument: --encrypt-vault-id" },
    { "VaultEncrypt stray", "unexpected argument: stray" },
    { "VaultCreate one two", "expected at most 1 file name" },
    { "VaultCreate", "requires a file path" },
  }
  for _, case in ipairs(arg_errors) do
    tests["argument error: " .. case[1]] = function()
      local fake = H.create_fake_vault()
      H.reset_config(fake)
      local buf = H.new_buffer({ "plain: value" })
      local before = H.lines(buf)
      H.command_fails(case[1])
      yes(H.notification_contains(case[2]), H.notification_text())
      eq(H.lines(buf), before, "an argument error must not touch the buffer")
      eq(H.calls(fake), 0, "an argument error must not start the child")
    end
  end

  tests["a credential path with spaces survives quoting and escaping"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local path = H.make_password_file(fake.dir, "secret", "quoted pass")

    local buf = H.new_buffer({ "plain: value" })
    vim.cmd('VaultEncrypt --vault-password-file "' .. path .. '"')
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    yes(H.log_has_line(fake.log, "ARG:" .. path), "a quoted path must arrive as exactly one argv item")

    -- Vim hands the backslashes to the command verbatim, so the plugin's own
    -- tokenizer is what has to put the path back together.
    local escaped = H.new_buffer({ "plain: value" })
    vim.cmd("VaultEncrypt --vault-password-file " .. path:gsub(" ", "\\ "))
    H.wait_until(function()
      return H.encrypted(escaped)
    end, "a backslash-escaped path must work too")
    eq(H.calls(fake, "encrypt"), 2)
    eq(
      select(2, H.read_file(fake.log):gsub("ARG:" .. vim.pesc(path), "")),
      2,
      "both spellings must reach the child as one argv item"
    )
  end

  tests["an explicit ask outranks a configured password file"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local prompts = 0
    H.patch(vim.fn, "inputsecret", function()
      prompts = prompts + 1
      return "secret"
    end)
    local buf = H.new_buffer({ "plain: value" })
    vim.cmd("VaultEncrypt --ask-vault-password")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    eq(prompts, 1, "--ask-vault-password is the only way to reach a password nothing has written down")
    yes(H.log_has_line(fake.log, "ENVPW:set"))
  end

  tests["a cancelled prompt runs nothing"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    H.patch(vim.fn, "inputsecret", function()
      return ""
    end)
    local buf = H.new_buffer({ "plain: value" })
    H.command_fails("VaultEncrypt")
    yes(H.notification_contains("Password is required"))
    no(H.encrypted(buf))
    eq(H.calls(fake), 0)
  end

  tests["a command vault-id replaces both configured lists"] = function()
    local fake = H.create_fake_vault()
    local dev = H.make_password_file(fake.dir, "secret", "dev pass")
    local prod = H.make_password_file(fake.dir, "other", "prod pass")
    local configured = H.reset_config(fake, { vault_ids = { "dev@" .. dev, "prod@" .. prod } })

    local buf = H.new_buffer({ "plain: value" })
    vim.cmd("VaultEncrypt --vault-id only@" .. vim.fn.fnameescape(dev))
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    yes(H.log_has_line(fake.log, "ARG:only@" .. dev), "the override should be the credential used")
    no(H.log_has_line(fake.log, "ARG:prod@" .. prod), "configured vault_ids must not survive the override")
    no(H.log_has_line(fake.log, "ARG:" .. configured.password_files), "nor must the configured password file")
  end

  tests["password_files outranks vault_ids"] = function()
    local fake = H.create_fake_vault()
    local pass = H.make_password_file(fake.dir)
    local ids = H.make_password_file(fake.dir, "secret", "id pass")
    H.reset_config(fake, { password_files = pass, vault_ids = { "prod@" .. ids } })
    local buf = H.new_buffer({ "plain: value" })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    yes(H.log_has_line(fake.log, "ARG:" .. pass))
    no(H.log_has_line(fake.log, "ARG:prod@" .. ids))
  end

  --- What the child is actually given ------------------------------------

  tests["the plugin identity is put ahead of the ansible.cfg list, which is kept"] = function()
    local fake = H.create_fake_vault()
    local root = H.make_project({ "[defaults]", "vault_identity_list = prod@.vault_pass" })
    local mine = H.make_password_file(fake.dir, "my-secret", "mine")
    H.reset_config(fake, { password_files = false, vault_ids = { "prod@" .. mine } })

    local creds = H.resolve_credentials(nil, { file_path = root .. "/group_vars/prod/vault.yml" })
    yes(creds ~= nil, "resolution should succeed")
    -- ansible-vault encrypts with the FIRST secret whose label matches, and it
    -- builds the pool from DEFAULT_VAULT_IDENTITY_LIST before the --vault-id
    -- flags. Same label, ansible.cfg first, means the file is sealed with a
    -- password the user did not choose: exit 0, expected header, wrong key.
    eq(
      creds.env.ANSIBLE_VAULT_IDENTITY_LIST,
      "prod@" .. mine .. ",prod@" .. root .. "/.vault_pass",
      "ours first, and the configured entry still there so its content still opens"
    )
    eq(creds.args, { "--vault-id", "prod@" .. mine })
    eq(creds.cwd, root, "the child runs where the config was found, so relative paths resolve")
    eq(creds.env.ANSIBLE_ASK_VAULT_PASS, "False", "the child must never try to prompt on a pipe")
  end

  tests["a vault id source containing a comma fails closed"] = function()
    local fake = H.create_fake_vault()
    local root = H.make_project({ "[defaults]", "vault_identity_list = prod@.vault_pass" })
    vim.fn.mkdir(fake.dir .. "/has,comma", "p")
    local odd = fake.dir .. "/has,comma/pass"
    H.write_file(odd, "secret\n")
    H.reset_config(fake, { password_files = false, vault_ids = { "prod@" .. odd } })

    H.clear_notifications()
    local creds = H.resolve_credentials(nil, { file_path = root .. "/group_vars/prod/vault.yml" })
    eq(creds, nil, "continuing would encrypt with ansible.cfg's password instead of the named one")
    yes(H.notification_contains("cannot express"), H.notification_text())
  end

  tests["ansible.cfg alone supplies credentials with no flags added"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local root = H.make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    local buf = H.new_file_buffer(root .. "/group_vars/prod", "vault.yml", { "plain: value" })

    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    -- Passing a flag on top of ansible.cfg is what makes ansible-vault fail with
    -- "The vault-ids default,default are available to encrypt".
    no(H.log_contains(fake.log, "ARG:--vault-password-file"), "no credential flag should be added")
    no(H.log_contains(fake.log, "ARG:--vault-id"), "no credential flag should be added")
    yes(H.log_has_line(fake.log, "CWD:" .. root), "the child must run where the config was found")
    yes(
      H.log_has_line(fake.log, "ENV:ANSIBLE_CONFIG=" .. root .. "/ansible.cfg"),
      "the child reads the config we found"
    )

    local described = credentials.describe(config.values, { file_path = root .. "/group_vars/prod/vault.yml" })
    eq(described.cfg_path, root .. "/ansible.cfg")
    eq(described.source, "ansible.cfg")
  end

  tests["a project .ansible.cfg supplies credentials to the child too"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local root = H.make_project({ "[defaults]", "vault_password_file = .vault_pass" }, ".ansible.cfg")
    local buf = H.new_file_buffer(root .. "/group_vars/prod", "vault.yml", { "plain: value" })

    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end, "a project .ansible.cfg must be enough to encrypt with, as the health report claims")
    -- Ansible reads `ansible.cfg` from its working directory but `.ansible.cfg`
    -- only from $HOME, so running the child in the right directory is not enough.
    yes(H.log_has_line(fake.log, "ENV:ANSIBLE_CONFIG=" .. root .. "/.ansible.cfg"), "the child must be told the path")
    eq(vim.env.ANSIBLE_CONFIG, nil, "naming it for the child must not change this process's environment")
  end

  tests["a relative ANSIBLE_CONFIG is settled before the child changes directory"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local root = H.make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    vim.fn.mkdir(root .. "/nested", "p")
    H.write_file(root .. "/nested/ansible.cfg", "[defaults]\nvault_password_file = .vault_pass\n")
    H.write_file(root .. "/nested/.vault_pass", "nestedsecret\n")

    local cfg = require("ansible-vault.ansible_cfg")
    vim.cmd("cd " .. vim.fn.fnameescape(root))
    local here = vim.fn.getcwd()
    -- A directory, which is the harder half of what ANSIBLE_CONFIG accepts.
    vim.env.ANSIBLE_CONFIG = "nested"
    cfg.clear_cache()

    local resolved = cfg.resolve(here .. "/group_vars/prod/vault.yml")
    eq(resolved.cfg_path, here .. "/nested/ansible.cfg", "the child runs elsewhere, so a relative path cannot survive")
    eq(resolved.settings.vault_password_file, here .. "/nested/.vault_pass")
    local creds = H.resolve_credentials(nil, { file_path = here .. "/group_vars/prod/vault.yml" })
    eq(creds.env.ANSIBLE_CONFIG, here .. "/nested/ansible.cfg")
    eq(vim.env.ANSIBLE_CONFIG, "nested", "the user's own environment must be left as it is")
  end

  tests["ANSIBLE_VAULT_PASSWORD_FILE outranks ansible.cfg"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local root = H.make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    vim.env.ANSIBLE_VAULT_PASSWORD_FILE = H.make_password_file(fake.dir)
    require("ansible-vault.ansible_cfg").clear_cache()
    local described = credentials.describe(config.values, { file_path = root .. "/group_vars/prod/vault.yml" })
    yes(described.source:find("ANSIBLE_* environment", 1, true) ~= nil, described.source)
  end

  tests["ansible.cfg is discovered upward and its relative paths resolve against it"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake, { password_files = false })
    local root = H.make_project({ "[defaults]", "vault_password_file = .vault_pass" })
    local cfg = require("ansible-vault.ansible_cfg")
    cfg.clear_cache()
    local resolved = cfg.resolve(root .. "/group_vars/prod/vault.yml")
    eq(resolved.settings.vault_password_file, root .. "/.vault_pass")
    eq(resolved.cwd, root)
    yes(resolved.has_credentials)
  end

  tests["several password files are one identity and are named explicitly"] = function()
    local fake = H.create_fake_vault()
    local first = H.make_password_file(fake.dir, "secret", "first pass")
    local second = H.make_password_file(fake.dir, "secret", "second pass")
    H.reset_config(fake, { password_files = { first, second } })

    local buf = H.new_buffer({ "plain: value" })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end, "several configured password files must not make encryption unavailable")
    yes(H.log_has_line(fake.log, "ARG:" .. first))
    yes(H.log_has_line(fake.log, "ARG:" .. second))
    -- ansible-vault counts secrets rather than labels, and refuses with "The
    -- vault-ids default,default are available to encrypt" unless one is named.
    yes(H.log_has_line(fake.log, "ARG:--encrypt-vault-id"))
    yes(H.log_has_line(fake.log, "ARG:default"))
  end

  tests["a 1.2 label survives re-encryption with only password_files configured"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_file_buffer(H.temp_dir(), "vault.yml", H.envelope("plain: old\n", nil, "prod"))
    vim.cmd("VaultDecrypt")
    H.wait_until(function()
      return H.lines(buf)[1] == "plain: old"
    end)
    eq(vim.b[buf].ansible_vault_label, "prod", "the label must be read while the ciphertext is still there")
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    eq(
      H.lines(buf)[1],
      "$ANSIBLE_VAULT;1.2;AES256;prod",
      "a password file has no label of its own, so it has to be given the file's"
    )
  end

  tests["rekey isolates the inherited encrypt identity and encrypt does not"] = function()
    eq(credentials.action_env("rekey"), { ANSIBLE_VAULT_ENCRYPT_IDENTITY = "" })
    eq(credentials.action_env("encrypt"), nil)
    eq(credentials.action_env("encrypt_string"), nil)
    eq(credentials.action_env("decrypt"), nil)

    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local buf = H.new_buffer({ "plain: value" })
    vim.cmd("VaultEncrypt")
    H.wait_until(function()
      return H.encrypted(buf)
    end)
    no(
      H.log_has_line(fake.log, "ENV:ANSIBLE_VAULT_ENCRYPT_IDENTITY="),
      "encrypt must keep honouring a configured encrypt identity"
    )
  end

  --- Rekey argv ----------------------------------------------------------

  tests["rekey builds new-credential flags and never passes --encrypt-vault-id"] = function()
    local function args(opts, context)
      local result, err = credentials.rekey_args(opts, context)
      eq(err, nil)
      return result
    end

    eq(args({ new_vault_id = "prod@/p" }), { "--new-vault-id", "prod@/p" })
    eq(args({ new_password_file = "/p" }), { "--new-vault-password-file", "/p" })
    -- A password file resolves to the id "default" and Ansible writes a 1.1
    -- envelope, dropping the label the file used to carry. Naming the label on
    -- the new identity is what keeps it.
    eq(args({ new_password_file = "/p" }, { header_label = "prod" }), { "--new-vault-id", "prod@/p" })
    eq(args({ new_password_file = "/p" }, { header_label = "default" }), { "--new-vault-password-file", "/p" })
    eq(args({ new_password_file = "/p", encrypt_vault_id = "named" }), { "--new-vault-id", "named@/p" })
    eq(args({}), nil, "nothing configured means nothing to rekey to")

    for _, result in ipairs({
      args({ new_vault_id = "prod@/p" }),
      args({ new_password_file = "/p" }, { header_label = "prod" }),
    }) do
      no(vim.tbl_contains(result, "--encrypt-vault-id"), "on rekey this flag can re-encrypt with the OLD password")
    end

    local _, err = credentials.rekey_args({ new_vault_id = "a@/b", new_password_file = "/c" })
    yes(err ~= nil and err:find("mutually exclusive", 1, true) ~= nil, tostring(err))
  end

  tests["inline rekey re-encrypts under the new identity alone"] = function()
    local fake = H.create_fake_vault()
    H.reset_config(fake)
    local creds, err = credentials.new_credentials({ new_password_file = "/new" }, { header_label = "prod" })
    eq(err, nil)
    eq(creds.args, { "--vault-id", "prod@/new", "--encrypt-vault-id", "prod" })
    -- Replaces whatever ansible.cfg configured: with the old identities still in
    -- the pool under the same label, "encrypt with the new password" resolves to
    -- the old one and the rekey silently changes nothing.
    eq(creds.env.ANSIBLE_VAULT_IDENTITY_LIST, "prod@/new")
    eq(creds.env.ANSIBLE_VAULT_ENCRYPT_IDENTITY, "")
    eq(creds.env.ANSIBLE_ASK_VAULT_PASS, "False")
    eq(select(1, credentials.new_credentials({}, {})), nil)

    -- The re-encrypt half is a separate run, so it needs the same config the
    -- decrypt half was given: without it the child finds no `.ansible.cfg` and
    -- the rekey fails halfway through.
    local root = H.make_project({ "[defaults]", "vault_password_file = .vault_pass" }, ".ansible.cfg")
    local rooted = credentials.new_credentials(
      { new_password_file = "/new" },
      { file_path = root .. "/group_vars/prod/vault.yml" }
    )
    eq(rooted.env.ANSIBLE_CONFIG, root .. "/.ansible.cfg")
    eq(rooted.cwd, root)
  end
end
