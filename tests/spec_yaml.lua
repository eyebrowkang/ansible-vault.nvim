---YAML parsing and formatting used by the inline lifecycle.
---@param H table
---@param tests table
return function(H, tests)
  local eq, yes, no = H.assert_eq, H.assert_true, H.assert_false
  local yaml = require("ansible-vault.yaml")

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

    -- A keyless list item's block body is indented from the sequence, not from
    -- past the dash, so two spaces is already a complete payload.
    yes(
      yaml.parse_block("- !vault |\n  $ANSIBLE_VAULT;1.2;AES256;prod\n  6162636465") ~= nil,
      "a keyless list payload indented two spaces is a block"
    )

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

  ---A literal block is indented relative to the node that owns it. For `- value`
  ---that node is the sequence entry itself, so the dash is not part of the body's
  ---indentation: `- |2-` with a four-space body is a value whose every line
  ---starts with two spaces, which is not what was decrypted. A keyed list item
  ---(`- key: |`) does own a mapping past the dash, and keeps its deeper body.
  tests["a literal block under a list dash is indented the way YAML reads it"] = function()
    local cases = {
      { "keyless list item", { indent = "", dash = "- " }, { "- |2-", "  first", "  second" } },
      { "nested keyless list item", { indent = "  ", dash = "- " }, { "  - |2-", "    first", "    second" } },
      {
        "keyed list item",
        { indent = "", dash = "- ", key_raw = "password" },
        {
          "- password: |2-",
          "    first",
          "    second",
        },
      },
      { "mapping key", { indent = "", dash = "", key_raw = "password" }, { "password: |2-", "  first", "  second" } },
    }
    for _, case in ipairs(cases) do
      eq(yaml.format_plaintext("first\nsecond", case[2], true), case[3], case[1] .. ": wrong body indentation")
      local parsed, err = yaml.parse_plaintext(case[3], true)
      yes(parsed ~= nil, case[1] .. ": " .. tostring(err))
      eq(parsed.content, "first\nsecond", case[1] .. ": the body must read back as it was written")
    end
  end

  tests["a keyless list value keeps its leading spaces and trailing newline"] = function()
    local written = yaml.format_plaintext("  indented\nnext\n", { indent = "", dash = "- " }, true)
    eq(written, { "- |2+", "    indented", "  next" })
    eq(yaml.parse_plaintext(written, true).content, "  indented\nnext\n")

    -- A plain keyless value continues on any line indented past the sequence, so
    -- a selection that stopped short of one is a half-selected value.
    eq(yaml.parse_plaintext({ "- plain" }, true).continues_at, 1)
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

  ---A quote is only a quote where YAML lets one start a scalar. An apostrophe in
  ---the middle of a plain value is data, so the `#` after it still opens a
  ---comment; reading that apostrophe as an opening quote swallows the comment
  ---into the value and encrypts a password nobody typed.
  tests["a quote only opens a scalar at its start"] = function()
    eq(yaml.unquote("don't # deployment password"), "don't", "an apostrophe in a plain scalar is data")
    eq(yaml.unquote('he said "hi" # note'), 'he said "hi"', "an internal double quote is data too")
    eq(yaml.unquote("plain#value # note"), "plain#value", "a # without leading space is not a comment")
    eq(yaml.unquote("'quoted # here' # note"), "quoted # here", "a quoted # is part of the value")
    eq(yaml.unquote([["sec#ret" # note]]), "sec#ret")
    eq(yaml.unquote("'don''t' # note"), "don't", "a doubled single quote is still one apostrophe")
    eq(yaml.unquote([["a \" b" # note]]), 'a " b', "an escaped double quote does not end the scalar")
    eq(yaml.strip_comment("don't # deployment password"), "don't ")
    eq(yaml.strip_comment("  'quoted # here' # note"), "  'quoted # here' ", "leading space still starts a scalar")
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
end
