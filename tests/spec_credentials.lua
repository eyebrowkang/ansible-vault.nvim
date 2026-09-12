---Configuration, command arguments, credential resolution, and the YAML shapes
---the inline lifecycle is built on.
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
  local yaml = require("ansible-vault.yaml")

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

    local described = credentials.describe(config.values, { file_path = root .. "/group_vars/prod/vault.yml" })
    eq(described.cfg_path, root .. "/ansible.cfg")
    eq(described.source, "ansible.cfg")
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
  end

  --- YAML shapes --------------------------------------------------------

  tests["every inline block shape ansible accepts is parsed"] = function()
    local body = "          $ANSIBLE_VAULT;1.2;AES256;prod\n          6162636465"
    local cases = {
      { "canonical", "password: !vault |\n" .. body, "password" },
      { "chomping indicator", "password: !vault |-\n" .. body, "password" },
      { "indent indicator", "password: !vault |2-\n" .. body, "password" },
      -- Ansible writes `|`, but a hand-written `>` block holds the same payload
      -- and refusing to read it would strand the value.
      { "folded scalar", "password: !vault >\n" .. body, "password" },
      { "trailing comment", "password: !vault | # note\n" .. body, "password" },
      { "double quoted key", '"password": !vault |\n' .. body, "password" },
      { "single quoted key", "'password': !vault |\n" .. body, "password" },
      { "colon inside a quoted key", "'a: b': !vault |\n" .. body, "a: b" },
      { "list item", "- password: !vault |\n" .. body, "password" },
      { "nested key", "    password: !vault |\n" .. body, "password" },
      { "bare list item", "- !vault |\n" .. body, nil },
    }
    for _, case in ipairs(cases) do
      local parsed = yaml.parse_block(case[2])
      yes(parsed ~= nil, case[1] .. ": failed to parse")
      eq(parsed.var_name, case[3], case[1] .. ": wrong key")
      eq(parsed.vault_content, "$ANSIBLE_VAULT;1.2;AES256;prod\n6162636465\n", case[1] .. ": unclean ciphertext")
      eq(parsed.header.label, "prod", case[1] .. ": vault id label was not read")
    end

    eq(yaml.parse_block("password: hunter2"), nil, "a plain value is not a vault block")
    eq(yaml.parse_block("password: !vault |"), nil, "a header with no ciphertext is not a block")
    eq(yaml.parse_block("password: !vault |\n          $ANSIBLE_VAULT;1.1;AES256"), nil, "no payload")
    eq(
      yaml.parse_block("password: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n            6162"),
      nil,
      "an unevenly indented payload is not one block"
    )
    eq(
      yaml.parse_block("password: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          61z2"),
      nil,
      "a payload must be hex"
    )
  end

  tests["a folded plaintext scalar is refused rather than guessed at"] = function()
    -- Reading a `>` envelope is safe; turning a folded *plaintext* scalar into
    -- one is not, because folding rewrites the value's newlines.
    local parsed, err = yaml.parse_plaintext({ "password: >", "  first", "  second" }, true)
    eq(parsed, nil)
    yes(err ~= nil and err:find("folded", 1, true) ~= nil, tostring(err))
  end

  tests["carriage returns never reach ansible-vault"] = function()
    local parsed = yaml.parse_block("password: !vault |\r\n          $ANSIBLE_VAULT;1.1;AES256\r\n          6162\r")
    yes(parsed ~= nil, "a CRLF block should parse")
    eq(parsed.vault_content, "$ANSIBLE_VAULT;1.1;AES256\n6162\n")
  end

  tests["header parsing reads version and label and rejects non-headers"] = function()
    eq(yaml.parse_header("$ANSIBLE_VAULT;1.2;AES256;prod"), { version = "1.2", cipher = "AES256", label = "prod" })
    eq(yaml.parse_header("$ANSIBLE_VAULT;1.1;AES256"), { version = "1.1", cipher = "AES256" })
    eq(yaml.parse_header("          $ANSIBLE_VAULT;1.2;AES256;dev").label, "dev")
    eq(yaml.parse_header("not a header"), nil)
    eq(yaml.parse_header("$ANSIBLE_VAULT;x;AES256"), nil)
    eq(yaml.parse_header("$ANSIBLE_VAULT;1.1"), nil)
  end

  tests["an envelope is validated before it can replace anything"] = function()
    eq(yaml.vault_lines("$ANSIBLE_VAULT;1.1;AES256\n6162\n"), { "$ANSIBLE_VAULT;1.1;AES256", "6162" })
    eq(yaml.vault_lines("$ANSIBLE_VAULT;1.1;AES256\n"), nil, "a header alone is not an envelope")
    eq(yaml.vault_lines(""), nil)
    eq(yaml.vault_lines("not a vault file\n6162\n"), nil)
    eq(yaml.vault_lines("$ANSIBLE_VAULT;1.1;AES256\n616\n"), nil, "an odd number of hex digits is not a payload")
    eq(yaml.vault_lines("$ANSIBLE_VAULT;1.1;AES256\nnothex\n"), nil)
  end

  tests["only the ciphertext is taken from encrypt_string output"] = function()
    -- The key ansible-vault echoes back is its own re-rendering of --stdin-name,
    -- which is not always the YAML the user wrote.
    local output = "renamed_key: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162\n"
    eq(yaml.extract_envelope(output), { "$ANSIBLE_VAULT;1.1;AES256", "6162" })
    eq(yaml.extract_envelope("no envelope here"), nil)
    eq(yaml.format_vault(output, { indent = "  ", dash = "- ", key_raw = "'a: b'" }), {
      "  - 'a: b': !vault |",
      "      $ANSIBLE_VAULT;1.1;AES256",
      "      6162",
    })
    local lines, err = yaml.format_vault("garbage", {})
    eq(lines, nil)
    yes(err ~= nil)
  end

  tests["a block is only found when the cursor is inside it"] = function()
    local lines = {
      "before: x",
      "password: !vault |",
      "          $ANSIBLE_VAULT;1.1;AES256",
      "          6162",
      "after: y",
    }
    eq({ yaml.find_block(lines, 2) }, { 2, 4 })
    eq({ yaml.find_block(lines, 4) }, { 2, 4 })
    eq({ yaml.find_block(lines, 5) }, {}, "a line below the payload is not inside the block")
    eq({ yaml.find_block(lines, 1) }, {}, "nor is a line above it")
  end

  tests["values that would be ambiguous as bare YAML are quoted"] = function()
    local ambiguous = { "", "true", "no", "null", " leading", "trailing ", "a: b", "#comment", "- item", "1.5" }
    for _, value in ipairs(ambiguous) do
      yes(yaml.needs_quoting(value), string.format("%q must be quoted", value))
      local quoted = yaml.quote_value(value)
      eq(yaml.unquote(quoted), value, string.format("%q must survive quoting", value))
    end
    for _, value in ipairs({ "plain", "some value", "a-b_c" }) do
      no(yaml.needs_quoting(value), string.format("%q needs no quoting", value))
      eq(yaml.quote_value(value), value)
    end
  end

  --- Health -------------------------------------------------------------

  tests["checkhealth reports the credential in effect without creating one"] = function()
    local fake = H.create_fake_vault()
    local pass = H.make_password_file(fake.dir)
    local script = H.temp_dir() .. "/health.lua"
    H.write_file(
      script,
      string.format(
        [[
vim.opt.runtimepath:prepend(%q)
require('ansible-vault').setup({ ansible_vault_path = %q, password_files = %q })
vim.cmd('checkhealth ansible-vault')
local report = table.concat(vim.api.nvim_buf_get_lines(0, 0, -1, false), '\n')
assert(report:find('ansible-vault.nvim', 1, true), report)
assert(report:find('Credential source: password_files', 1, true), report)
assert(report:find(%q, 1, true), report)
assert(not report:find('E5108', 1, true), report)
for _, forbidden in ipairs({'User Events', 'statusline', 'ansible_vault_password'}) do
  assert(not report:find(forbidden, 1, true), 'health still reports ' .. forbidden .. ':\n' .. report)
end
-- A diagnostic that installs the password helper would be reporting on a state
-- it created itself.
assert(vim.fn.filereadable(vim.fn.stdpath('run') .. '/ansible-vault.nvim/askpass.sh') == 0, 'health created a helper')
io.stdout:write('HEALTH_OK\n'); io.stdout:flush()
]],
        H.root,
        fake.path,
        pass,
        pass
      )
    )
    local helper = H.askpass_path()
    vim.fn.delete(helper)
    local result = vim.system({ vim.v.progpath, "--headless", "-u", "NONE", "-l", script }):wait(20000)
    eq(result.code, 0, result.stdout .. result.stderr)
    yes(result.stdout:find("HEALTH_OK", 1, true))
  end
end
