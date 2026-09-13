---The claims only the real `ansible-vault` can settle.
---
---The fake in `make test` is byte-exact but deliberately not an authority on
---Ansible's own secret precedence. Everything here runs against ansible-core, and
---every claim about *which password* a file ended up under is checked by a
---separate `ansible-vault decrypt` invocation — never by an exit code and never
---by the header, because the two ways a rekey can silently do nothing both
---produce exit 0 and the expected header.
vim.opt.runtimepath:prepend(vim.fn.getcwd())

local vault = require("ansible-vault")

local ansible_vault = vim.env.ANSIBLE_VAULT_NVIM_REAL_BIN
if not ansible_vault or ansible_vault == "" then
  ansible_vault = vim.fn.getcwd() .. "/.venv/bin/ansible-vault"
end
if vim.fn.executable(ansible_vault) ~= 1 then
  error("real ansible-vault binary is not executable: " .. ansible_vault)
end

-- PyYAML comes from the same environment as the real binary, so what the plugin
-- wrote is read back by an actual YAML parser rather than by the plugin's own.
local python = vim.fn.fnamemodify(ansible_vault, ":h") .. "/python"
if vim.fn.executable(python) ~= 1 then
  python = vim.fn.getcwd() .. "/.venv/bin/python"
end
if vim.fn.executable(python) ~= 1 then
  error("a Python with PyYAML is required beside " .. ansible_vault)
end

-- The ambient environment must not decide what these tests resolve.
for key in pairs(vim.fn.environ()) do
  if key:match("^ANSIBLE_") then
    vim.env[key] = nil
  end
end
vim.o.hidden = true
vim.o.swapfile = false

--- Harness -----------------------------------------------------------------

local failures, ran = 0, 0
local notifications = {}

local function fail(message)
  error(message, 2)
end

local S = dofile(vim.fn.getcwd() .. "/tests/support.lua")
local assert_eq, assert_true = S.assert_eq, S.assert_true
local write_file, read_file, temp_dir = S.write_file, S.read_file, S.temp_dir
local lines, open_file = S.lines, S.open_file

local function wait_until(predicate, message)
  if not vim.wait(20000, predicate, 20) then
    fail(message or "timed out waiting for condition")
  end
end

local function password_file(dir, name, value)
  local path = dir .. "/" .. name
  write_file(path, value .. "\n")
  vim.fn.setfperm(path, "rw-------")
  return path
end

---Run the real binary directly. This is the independent oracle: nothing the
---plugin does is trusted to report on itself.
local function run_vault(args, stdin)
  local argv = { ansible_vault }
  vim.list_extend(argv, args)
  return vim.system(argv, { stdin = stdin, text = false }):wait(60000)
end

---Parse a YAML document with PyYAML and hand back what it holds.
---
---The independent oracle for the YAML the plugin writes: a value is only really
---preserved if a parser that has never seen this code reads the same bytes back.
---@param text string
---@return any
local function yaml_load(text)
  local result = vim
    .system({
      python,
      "-c",
      "import json, sys, yaml; json.dump(yaml.safe_load(sys.stdin.read()), sys.stdout)",
    }, { stdin = text, text = true })
    :wait(60000)
  assert_eq(result.code, 0, "PyYAML could not read the document: " .. tostring(result.stderr))
  return vim.json.decode(result.stdout)
end

---@return boolean opened, string plaintext
local function opens_with(pass, path)
  local result = run_vault({ "decrypt", "--vault-password-file", pass, "--output", "-", path })
  return result.code == 0, result.stdout or ""
end

---The two-sided rekey assertion: only "the new password works and the old one
---does not" distinguishes a real rotation from one that reported success and
---changed nothing.
local function assert_rotated(path, old_pass, new_pass, expected, label)
  local new_ok, plaintext = opens_with(new_pass, path)
  assert_true(new_ok, label .. ": the NEW password must open the rekeyed file")
  assert_eq(plaintext, expected, label .. ": the content must survive the rekey")
  local old_ok = opens_with(old_pass, path)
  assert_true(not old_ok, label .. ": the OLD password must NOT open the rekeyed file")
end

---Encrypt a fixture with the real binary, so no fixture is produced by the code
---being tested.
local function make_vault_file(dir, name, content, vault_id, pass)
  local path = dir .. "/" .. name
  write_file(path, content)
  local args = { "encrypt" }
  if vault_id then
    vim.list_extend(args, { "--vault-id", vault_id .. "@" .. pass })
  else
    vim.list_extend(args, { "--vault-password-file", pass })
  end
  table.insert(args, path)
  local result = run_vault(args)
  assert_eq(result.code, 0, "failed to build fixture " .. name .. ": " .. tostring(result.stderr))
  return path
end

local function reset(opts)
  require("ansible-vault.ansible_cfg").clear_cache()
  local config = { ansible_vault_path = ansible_vault }
  for key, value in pairs(opts or {}) do
    config[key] = value
  end
  vault.setup(config)
end

local function fresh_buffers()
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
  end
end

---Run one check, and leave the environment as it was found.
---
---A check that sets an `ANSIBLE_*` variable and clears it on the way out never
---gets there if it fails, and because a failure here is reported and execution
---continues, that variable would then be in force for every later check. So the
---restoration happens here, where a failure cannot skip it.
local function check(name, fn)
  ran = ran + 1
  io.stdout:write("REAL ", name, "\n")
  io.stdout:flush()

  local env_before = {}
  for key, value in pairs(vim.fn.environ()) do
    if key:match("^ANSIBLE_") then
      env_before[key] = value
    end
  end

  local notify = vim.notify
  notifications = {}
  vim.notify = function(message, level)
    table.insert(notifications, { message = tostring(message), level = level })
  end
  local ok, err = xpcall(fn, debug.traceback)
  vim.notify = notify

  fresh_buffers()
  for key in pairs(vim.fn.environ()) do
    if key:match("^ANSIBLE_") and env_before[key] == nil then
      vim.env[key] = nil
    end
  end
  for key, value in pairs(env_before) do
    vim.env[key] = value
  end

  if not ok then
    failures = failures + 1
    io.stderr:write("FAILED ", name, "\n", tostring(err), "\n")
    io.stderr:flush()
  end
end

--- Whole-file lifecycle ----------------------------------------------------

check("whole Decrypt then :w saves the exact plaintext bytes", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  -- Every shape of trailing newline, plus CRLF, through real Ansible. The last
  -- three end in a carriage return with no final newline, where that byte has no
  -- line ending to live in and is easy to drop.
  local cases = {
    { "plain.yml", "plain: value\n" },
    { "noeol.yml", "plain: value" },
    { "blanks.yml", "plain: value\n\n\n" },
    { "crlf.yml", "a: 1\r\nb: 2\r\n" },
    { "trailing-cr.yml", "a\r" },
    { "bare-cr.yml", "\r" },
    { "crlf-then-cr.yml", "a\r\nb\r" },
  }
  for _, case in ipairs(cases) do
    local path = make_vault_file(dir, case[1], case[2], nil, pass)
    local buf = open_file(path)
    vim.cmd("VaultDecrypt")
    wait_until(function()
      return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") == nil
    end, case[1] .. ": decrypt did not finish")
    vim.cmd("silent write")
    assert_eq(read_file(path), case[2], case[1] .. ": :w after VaultDecrypt must save the plaintext byte for byte")
    fresh_buffers()
  end
end)

check("whole Encrypt then :w saves ciphertext only", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  local path = dir .. "/live.yml"
  write_file(path, "api_key: SUPERSECRET\n")
  local buf = open_file(path)
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "encrypt did not finish")
  vim.cmd("silent write")

  local contents = read_file(path)
  assert_true(contents:match("^%$ANSIBLE_VAULT"), "the file should be ciphertext")
  assert_true(contents:find("SUPERSECRET", 1, true) == nil, "plaintext reached disk")
  local ok, plaintext = opens_with(pass, path)
  assert_true(ok, "the configured password should open it")
  assert_eq(plaintext, "api_key: SUPERSECRET\n", "the content must round trip")
end)

check("whole Edit writes ciphertext the same password opens", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })
  local path = make_vault_file(dir, "edit.yml", "plain: before\n", nil, pass)

  local source = open_file(path)
  vim.cmd("VaultEdit")
  wait_until(function()
    return vim.api.nvim_get_current_buf() ~= source
  end, "VaultEdit did not open a scratch buffer")
  local scratch = vim.api.nvim_get_current_buf()
  assert_eq(lines(scratch), { "plain: before" }, "the scratch should hold the decrypted file")

  vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "plain: after", "extra: line" })
  vim.cmd("silent write")
  assert_true(vim.api.nvim_buf_is_valid(scratch), "the scratch stays open so it can be saved again")

  local ok, plaintext = opens_with(pass, path)
  assert_true(ok, "the edited file should open with the same password")
  assert_eq(plaintext, "plain: after\nextra: line\n")
end)

check("Create writes a file that only ever held ciphertext", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  local path = dir .. "/created.yml"
  vim.cmd("VaultCreate " .. vim.fn.fnameescape(path))
  assert_eq(vim.fn.filereadable(path), 0, "nothing should exist on disk before the first write")
  vim.api.nvim_buf_set_lines(0, 0, -1, false, { "brand: new" })
  vim.cmd("silent write")
  assert_true(read_file(path):match("^%$ANSIBLE_VAULT"), "VaultCreate must write ciphertext")
  assert_eq(vim.fn.getfperm(path), "rw-------", "a new vault file must not be world readable")
  local ok, plaintext = opens_with(pass, path)
  assert_true(ok)
  assert_eq(plaintext, "brand: new\n")
end)

check("a 1.2 vault id label survives Decrypt then Encrypt", function()
  local dir = temp_dir()
  local pass = password_file(dir, "prod-pass", "prodsecret")
  local path = make_vault_file(dir, "labelled.yml", "plain: labelled\n", "prod", pass)
  assert_true(
    read_file(path):match("^%$ANSIBLE_VAULT;1%.2;AES256;prod") ~= nil,
    "fixture should be a labelled 1.2 file"
  )

  reset({ vault_ids = { "prod@" .. pass } })
  local buf = open_file(path)
  vim.cmd("VaultDecrypt")
  wait_until(function()
    return lines(buf)[1] == "plain: labelled"
  end, "decrypt of the labelled file did not finish")
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "re-encrypt did not finish")
  vim.cmd("silent write")

  assert_eq(
    read_file(path):match("^[^\n]*"),
    "$ANSIBLE_VAULT;1.2;AES256;prod",
    "re-encrypting must not rewrite the file as 1.1 and drop its label"
  )
  local ok, plaintext = opens_with(pass, path)
  assert_true(ok)
  assert_eq(plaintext, "plain: labelled\n")
end)

check("only password_files configured still keeps a 1.2 label", function()
  local dir = temp_dir()
  local pass = password_file(dir, "prod-pass", "prodsecret")
  local path = make_vault_file(dir, "labelled.yml", "plain: labelled\n", "prod", pass)

  -- A password file has no label of its own, so the label has to come from the
  -- file's own header or this save fails outright.
  reset({ password_files = pass })
  local buf = open_file(path)
  vim.cmd("VaultDecrypt")
  wait_until(function()
    return lines(buf)[1] == "plain: labelled"
  end, "decrypt did not finish")
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "re-encrypt with only password_files did not finish")
  vim.cmd("silent write")
  assert_eq(read_file(path):match("^[^\n]*"), "$ANSIBLE_VAULT;1.2;AES256;prod")
  assert_true(select(1, opens_with(pass, path)))
end)

--- Inline values ---------------------------------------------------------

---Pull the `!vault` block out of the buffer and write it out as a vault file, so
---the value can be read back through actual cryptography rather than through the
---code that put it there.
local function extract_envelope(buf, dir, name)
  local block = {}
  local started = false
  for _, line in ipairs(lines(buf)) do
    if line:match("^%s*%$ANSIBLE_VAULT;") then
      started = true
    end
    if started then
      if not line:match("^%s*%x+%s*$") and not line:match("^%s*%$ANSIBLE_VAULT;") then
        break
      end
      table.insert(block, (line:gsub("^%s+", "")))
    end
  end
  assert_true(#block >= 2, "no vault envelope was found in the buffer")
  local path = dir .. "/" .. (name or "extracted.vault")
  write_file(path, table.concat(block, "\n") .. "\n")
  return path, #block
end

local function decrypt_inline(buf, pass, dir)
  local path = extract_envelope(buf, dir)
  local ok, plaintext = opens_with(pass, path)
  assert_true(ok, "the extracted inline envelope should decrypt")
  return plaintext
end

check("range Encrypt preserves each value's exact bytes through real Ansible", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  local cases = {
    { { "password: secret" }, "secret" },
    { { "password: |-", "  first", "  second" }, "first\nsecond" },
    { { "password: |", "  first", "  second" }, "first\nsecond\n" },
    { { "password: |+", "  first", "", "" }, "first\n\n\n" },
    { { "password: |2-", "    indented", "  normal" }, "  indented\nnormal" },
    { { "    - password: value" }, "value" },
  }
  for index, case in ipairs(cases) do
    local buf = vim.api.nvim_create_buf(true, false)
    vim.api.nvim_set_current_buf(buf)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, case[1])
    vim.cmd("1," .. #case[1] .. "VaultEncrypt")
    wait_until(function()
      return table.concat(lines(buf), "\n"):find("!vault", 1, true) ~= nil
    end, "case " .. index .. ": inline encrypt did not finish")
    assert_eq(decrypt_inline(buf, pass, dir), case[2], "case " .. index .. ": the value's bytes must be preserved")
    fresh_buffers()
  end
end)

---An upstream limitation, not a plugin decision: `ansible-vault encrypt_string`
---refuses empty stdin with "[ERROR]: stdin was empty, not encrypting". The
---plugin cannot encrypt an empty value, so what matters is that it says so and
---leaves the buffer exactly as it was.
check("an empty inline value is refused without changing the buffer", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  local input = { 'password: ""', "other: keep" }
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, input)
  vim.bo[buf].modified = false
  vim.cmd("1VaultEncrypt")
  wait_until(function()
    for _, item in ipairs(notifications) do
      if item.level == vim.log.levels.ERROR and item.message:find("Encryption failed", 1, true) then
        return true
      end
    end
    return false
  end, "empty inline encryption must finish with an error notification")
  assert_eq(lines(buf), input, "a refused encryption must leave the selection alone")
  assert_true(not vim.bo[buf].modified, "a refused encryption must not mark the buffer modified")

  -- A successful retry proves the failed child completed and released the buffer.
  vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "password: retry" })
  vim.cmd("1VaultEncrypt")
  wait_until(function()
    return lines(buf)[1] == "password: !vault |"
  end, "the buffer must accept another operation after the failure")
  assert_eq(decrypt_inline(buf, pass, dir), "retry")
  assert_eq(lines(buf)[#lines(buf)], "other: keep")
end)

check("inline Decrypt then range Encrypt round trips through real Ansible", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  -- Build the block with the real binary via the plugin, then take it apart.
  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "password: |", "  one", "  two" })
  vim.cmd("1,3VaultEncrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) ~= nil
  end, "inline encrypt did not finish")
  assert_eq(decrypt_inline(buf, pass, dir), "one\ntwo\n")

  vim.api.nvim_win_set_cursor(0, { 1, 0 })
  vim.cmd("VaultDecrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) == nil
  end, "inline decrypt did not finish")
  assert_eq(lines(buf), { "password: |2+", "  one", "  two" }, "the value must come back as a literal block")

  vim.cmd("1,3VaultEncrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) ~= nil
  end, "re-encrypt did not finish")
  assert_eq(decrypt_inline(buf, pass, dir), "one\ntwo\n", "the value must survive a full round trip")
end)

---A keyless list item (`- !vault |`) has no mapping past its dash, so the block
---it decrypts into is indented from the sequence. A body pushed two spaces
---further is still valid YAML — and is silently a different value, with two
---leading spaces on every line. Only a real parser can settle that.
check("a keyless list item decrypts to the value YAML reads back", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "- |", "  first", "  second", "- other" })
  vim.cmd("1,3VaultEncrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) ~= nil
  end, "keyless list encrypt did not finish")
  assert_eq(decrypt_inline(buf, pass, dir), "first\nsecond\n", "the list item's bytes must reach Ansible intact")

  vim.api.nvim_win_set_cursor(0, { 1, 0 })
  vim.cmd("VaultDecrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) == nil
  end, "keyless list decrypt did not finish")

  local document = yaml_load(table.concat(lines(buf), "\n") .. "\n")
  assert_eq(document[1], "first\nsecond\n", "PyYAML must read back exactly the decrypted bytes")
  assert_eq(document[2], "other", "the neighbouring list item must still be its own value")

  vim.cmd("1," .. (#lines(buf) - 1) .. "VaultEncrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) ~= nil
  end, "keyless list re-encrypt did not finish")
  assert_eq(decrypt_inline(buf, pass, dir), "first\nsecond\n", "the value must survive a full round trip")
end)

check("inline Edit writes the edited value back into the buffer only", function()
  local dir = temp_dir()
  local pass = password_file(dir, "pass", "secret")
  reset({ password_files = pass })

  local path = dir .. "/vars.yml"
  write_file(path, "before: keep\npassword: original\nafter: keep\n")
  local source = open_file(path)
  vim.cmd("2VaultEncrypt")
  wait_until(function()
    return table.concat(lines(source), "\n"):find("!vault", 1, true) ~= nil
  end, "inline encrypt did not finish")
  vim.cmd("silent write")
  local on_disk = read_file(path)

  vim.api.nvim_win_set_cursor(0, { 2, 0 })
  vim.cmd("VaultEdit")
  wait_until(function()
    return vim.api.nvim_get_current_buf() ~= source
  end, "inline VaultEdit did not open a scratch buffer")
  local scratch = vim.api.nvim_get_current_buf()
  assert_eq(lines(scratch), { "original" }, "the scratch should hold just the value")

  vim.api.nvim_buf_set_lines(scratch, 0, -1, false, { "rotated" })
  vim.cmd("silent write")
  assert_eq(read_file(path), on_disk, "an inline edit must never save the source YAML")
  assert_true(vim.bo[source].modified, "the source is left for the user to save")
  -- No trailing newline: the value it opened with had none, and 'endofline'
  -- carries that through the edit.
  assert_eq(decrypt_inline(source, pass, dir), "rotated", "the new value must be what the block now holds")
  assert_eq(lines(source)[1], "before: keep")
  assert_eq(lines(source)[#lines(source)], "after: keep")
end)

--- Rekey -----------------------------------------------------------------

check("whole Rekey 1.1 really changes the password", function()
  local dir = temp_dir()
  local old = password_file(dir, "old", "old-secret")
  local new = password_file(dir, "new", "new-secret")
  local path = make_vault_file(dir, "secret.yml", "token: original\n", nil, old)

  reset({ password_files = old })
  open_file(path)
  local before = read_file(path)
  vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
  wait_until(function()
    local now = read_file(path)
    return now ~= before and now:match("^%$ANSIBLE_VAULT") ~= nil
  end, "the rekey did not rewrite the file as a complete envelope")

  assert_rotated(path, old, new, "token: original\n", "1.1 rekey")
end)

check("whole Rekey keeps a 1.2 label and really changes the password", function()
  local dir = temp_dir()
  local old = password_file(dir, "old", "old-secret")
  local new = password_file(dir, "new", "new-secret")
  local path = make_vault_file(dir, "secret.yml", "token: original\n", "prod", old)

  reset({ vault_ids = "prod@" .. old })
  open_file(path)
  local before = read_file(path)
  vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
  wait_until(function()
    local now = read_file(path)
    return now ~= before and now:match("^%$ANSIBLE_VAULT") ~= nil
  end, "the rekey did not rewrite the file")

  assert_true(read_file(path):match("^%$ANSIBLE_VAULT;1%.2;AES256;prod") ~= nil, "the 1.2 label must survive a rekey")
  assert_rotated(path, old, new, "token: original\n", "1.2 rekey")
end)

---Behaviour 1, verified against ansible-core 2.21.4.
---
---`ansible-vault rekey` reads `--encrypt-vault-id` *or* the inherited
---`DEFAULT_VAULT_ENCRYPT_IDENTITY`, and if either is set it seeds the pool of
---NEW secrets with the OLD identities and then matches by label. With an
---`ansible.cfg` that sets `vault_encrypt_identity` to a label the old
---configuration also carries, the rekey prints "Rekey successful", writes the
---same 1.2 header back, and leaves the file on its OLD password.
check("an ansible.cfg encrypt identity cannot make a rekey a silent no-op", function()
  local dir = temp_dir()
  local old = password_file(dir, "old-pass", "old-secret")
  local new = password_file(dir, "new-pass", "new-secret")
  write_file(dir .. "/ansible.cfg", "[defaults]\nvault_identity_list = prod@old-pass\nvault_encrypt_identity = prod\n")
  local path = make_vault_file(dir, "secret.yml", "token: original\n", "prod", old)

  -- Nothing configured in the plugin: ansible.cfg is the credential source, and
  -- the encrypt identity is inherited exactly as a user's project would.
  reset({})
  open_file(path)
  local before = read_file(path)
  vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
  wait_until(function()
    local now = read_file(path)
    return now ~= before and now:match("^%$ANSIBLE_VAULT") ~= nil
  end, "the rekey did not rewrite the file")

  -- Exit code and header are both useless here: the broken case produces both.
  assert_rotated(path, old, new, "token: original\n", "inherited encrypt identity")
end)

check("an inherited encrypt identity in the environment cannot make a rekey a no-op", function()
  local dir = temp_dir()
  local old = password_file(dir, "old-pass", "old-secret")
  local new = password_file(dir, "new-pass", "new-secret")
  write_file(dir .. "/ansible.cfg", "[defaults]\nvault_identity_list = prod@old-pass\n")
  local path = make_vault_file(dir, "secret.yml", "token: original\n", "prod", old)

  vim.env.ANSIBLE_VAULT_ENCRYPT_IDENTITY = "prod"
  reset({})
  open_file(path)
  local before = read_file(path)
  vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
  wait_until(function()
    local now = read_file(path)
    return now ~= before and now:match("^%$ANSIBLE_VAULT") ~= nil
  end, "the rekey did not rewrite the file")

  -- No manual cleanup: `check` restores ANSIBLE_* however this ends.
  assert_rotated(path, old, new, "token: original\n", "inherited ANSIBLE_VAULT_ENCRYPT_IDENTITY")
end)

check("inline Rekey really changes the password for that value", function()
  local dir = temp_dir()
  local old = password_file(dir, "old", "old-secret")
  local new = password_file(dir, "new", "new-secret")
  reset({ password_files = old })

  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "password: rotate-me" })
  vim.cmd("1VaultEncrypt")
  wait_until(function()
    return table.concat(lines(buf), "\n"):find("!vault", 1, true) ~= nil
  end, "inline encrypt did not finish")

  local before = table.concat(lines(buf), "\n")
  -- No range: a real envelope is many lines long, and the cursor sitting in the
  -- block is how this is used.
  vim.api.nvim_win_set_cursor(0, { 1, 0 })
  vim.cmd("VaultRekey --new-vault-password-file " .. vim.fn.fnameescape(new))
  wait_until(function()
    return table.concat(lines(buf), "\n") ~= before
  end, "inline rekey did not rewrite the value")

  -- Same two-sided check, on the extracted envelope.
  local path = extract_envelope(buf, dir, "inline.vault")
  assert_rotated(path, old, new, "rotate-me", "inline rekey")
end)

--- ansible.cfg and identity precedence ------------------------------------

check("ansible.cfg alone supplies credentials", function()
  local dir = temp_dir()
  vim.fn.mkdir(dir .. "/group_vars/prod", "p")
  local pass = password_file(dir, ".vault_pass", "cfgsecret")
  write_file(dir .. "/ansible.cfg", "[defaults]\nvault_password_file = .vault_pass\n")

  reset({})
  local path = dir .. "/group_vars/prod/vault.yml"
  write_file(path, "db_password: fromcfg\n")
  local buf = open_file(path)
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "encrypting with ansible.cfg credentials failed")
  vim.cmd("silent write")
  local ok, plaintext = opens_with(pass, path)
  assert_true(ok, "the ansible.cfg password should open it")
  assert_eq(plaintext, "db_password: fromcfg\n")

  vim.cmd("VaultDecrypt")
  wait_until(function()
    return lines(buf)[1] == "db_password: fromcfg"
  end, "decrypting with ansible.cfg credentials failed")
end)

---This is what "The vault-ids default,default are available to encrypt" looks
---like when it is not handled: a configured password file alongside an
---ansible.cfg identity.
check("a configured password file works alongside an ansible.cfg identity", function()
  local dir = temp_dir()
  vim.fn.mkdir(dir .. "/group_vars/prod", "p")
  password_file(dir, ".vault_pass", "cfgsecret")
  write_file(dir .. "/ansible.cfg", "[defaults]\nvault_password_file = .vault_pass\n")
  local own = password_file(dir, "own_pass", "ownsecret")

  reset({ password_files = own })
  local path = dir .. "/group_vars/prod/clash.yml"
  write_file(path, "clash: value\n")
  local buf = open_file(path)
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "encrypting alongside an ansible.cfg identity failed")
  vim.cmd("silent write")
  assert_true(select(1, opens_with(own, path)), "the configured password file should be the one used")
end)

check("several configured password files still encrypt", function()
  local dir = temp_dir()
  local first = password_file(dir, "first", "secret")
  local second = password_file(dir, "second", "other")
  reset({ password_files = { first, second } })

  local path = dir .. "/multi.yml"
  write_file(path, "multi: value\n")
  local buf = open_file(path)
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "several password files must not make encryption unavailable")
  vim.cmd("silent write")
  assert_true(select(1, opens_with(first, path)), "the first identity is the one named for encryption")
end)

---Behaviour 2, verified against ansible-core 2.21.4.
---
---`ansible-vault` builds its secret pool as `DEFAULT_VAULT_IDENTITY_LIST` first
---and the `--vault-id` flags after it, then encrypts with the FIRST secret whose
---label matches. So an `ansible.cfg` that happens to use the same label as the
---credential the user named on the command line wins, and the file is encrypted
---with a password the user did not choose: exit 0, expected header, wrong key.
check("a named identity outranks an ansible.cfg entry with the same label", function()
  local dir = temp_dir()
  vim.fn.mkdir(dir .. "/group_vars", "p")
  local cfg_pass = password_file(dir, "cfg-pass", "cfg-secret")
  local mine = password_file(dir, "my-pass", "my-secret")
  write_file(dir .. "/ansible.cfg", "[defaults]\nvault_identity_list = prod@cfg-pass\n")

  reset({ vault_ids = { "prod@" .. mine } })
  local path = dir .. "/group_vars/named.yml"
  write_file(path, "chosen: value\n")
  local buf = open_file(path)
  vim.cmd("VaultEncrypt")
  wait_until(function()
    return (lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT") ~= nil
  end, "encrypt with a named identity failed")
  vim.cmd("silent write")

  local mine_ok, plaintext = opens_with(mine, path)
  assert_true(mine_ok, "the file must be sealed with the identity the user named")
  assert_eq(plaintext, "chosen: value\n")
  assert_true(
    not select(1, opens_with(cfg_pass, path)),
    "ansible.cfg's password must NOT be the one the file ended up under"
  )

  -- The configured entry is kept after ours, so content encrypted with it still
  -- opens.
  local cfg_file = make_vault_file(dir .. "/group_vars", "from_cfg.yml", "old: value\n", "prod", cfg_pass)
  local cfg_buf = open_file(cfg_file)
  vim.cmd("VaultDecrypt")
  wait_until(function()
    return lines(cfg_buf)[1] == "old: value"
  end, "content encrypted with the ansible.cfg identity must still decrypt")
end)

--- Report ----------------------------------------------------------------

if failures > 0 then
  io.stderr:write(string.format("REAL_SMOKE_FAILED %d of %d\n", failures, ran))
  io.stderr:flush()
  vim.cmd("cquit")
end

-- Flush explicitly: Neovim writes its own messages to the same stream, and on
-- exit this final line was sometimes lost, making a passing run look like a
-- failed one to anything grepping for the marker.
io.stdout:write(string.format("REAL_SMOKE_OK (%d checks)\n", ran))
io.stdout:flush()
vim.cmd("qa!")
