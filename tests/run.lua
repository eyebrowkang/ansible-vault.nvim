vim.opt.runtimepath:prepend(vim.fn.getcwd())

local vault = require("ansible-vault")

local notifications = {}
vim.notify = function(message, level)
  table.insert(notifications, { message = message, level = level })
end

local function fail(message)
  error(message, 2)
end

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    fail(string.format(
      "%s\nexpected: %s\nactual:   %s",
      message or "values are not equal",
      vim.inspect(expected),
      vim.inspect(actual)
    ))
  end
end

local function assert_true(value, message)
  if not value then
    fail(message or "expected value to be truthy")
  end
end

local function assert_false(value, message)
  if value then
    fail(message or "expected value to be falsy")
  end
end

local function wait_until(predicate, message)
  if not vim.wait(3000, predicate, 20) then
    fail(message or "timed out waiting for condition")
  end
end

local function write_file(path, contents)
  local file = assert(io.open(path, "w"))
  file:write(contents)
  file:close()
end

local function read_file(path)
  local file = assert(io.open(path, "r"))
  local contents = file:read("*a")
  file:close()
  return contents
end

local function temp_dir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

local function create_fake_vault()
  local dir = temp_dir()
  local path = dir .. "/fake vault"
  local log = dir .. "/vault.log"

  write_file(path, [=[
#!/bin/sh
if [ -n "$FAKE_VAULT_LOG" ]; then
  printf 'CALL\n' >> "$FAKE_VAULT_LOG"
  for arg in "$@"; do
    printf 'ARG:%s\n' "$arg" >> "$FAKE_VAULT_LOG"
  done
fi

action="$1"
shift
name="encrypted_string"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stdin-name)
      shift
      name="$1"
      ;;
  esac
  shift || break
done

input=$(cat)
if [ -n "$FAKE_VAULT_SLEEP" ]; then
  sleep "$FAKE_VAULT_SLEEP"
fi

case "$action" in
  encrypt)
    printf '$ANSIBLE_VAULT;1.1;AES256\n'
    printf 'ENC:%s\n' "$input"
    ;;
  decrypt)
    case "$input" in
      *EDITME*) printf 'plain: old\n' ;;
      *) printf 'plain: value\n' ;;
    esac
    ;;
  encrypt_string)
    printf '%s: !vault |\n' "$name"
    printf '          $ANSIBLE_VAULT;1.1;AES256\n'
    printf '          ENCSTR:%s\n' "$input"
    ;;
  *)
    printf 'unknown action: %s\n' "$action" >&2
    exit 2
    ;;
esac
]=])
  vim.fn.setfperm(path, "rwx------")

  return {
    dir = dir,
    path = path,
    log = log,
  }
end

local function make_password_file(base)
  local dir = base .. "/dir with space"
  vim.fn.mkdir(dir, "p")
  local path = dir .. "/pass file"
  write_file(path, "secret\n")
  vim.fn.setfperm(path, "rw-------")
  return path
end

local function reset_config(fake, opts)
  notifications = {}
  vim.env.FAKE_VAULT_LOG = fake.log
  vim.env.FAKE_VAULT_SLEEP = nil

  vault.config.password_file = nil
  vault.config.vault_id = nil
  vault.config.encrypt_vault_id = nil
  vault.config.auto_detect = true
  vault.config.conda_env = nil
  vault.config.ansible_vault_path = nil
  vault.config.debug = false

  local config = {
    ansible_vault_path = fake.path,
    auto_detect = false,
  }

  if not opts or opts.password_file ~= false then
    config.password_file = opts and opts.password_file or make_password_file(fake.dir)
  end

  for key, value in pairs(opts or {}) do
    if not (key == "password_file" and value == false) then
      config[key] = value
    end
  end

  vault.setup(config)
  return config
end

local function new_buffer(lines)
  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modified = false
  return buf
end

local function log_contains(log_path, expected)
  local contents = read_file(log_path)
  return contents:find(expected, 1, true) ~= nil
end

local function log_has_line(log_path, expected)
  for line in read_file(log_path):gmatch("[^\n]+") do
    if line == expected then
      return true
    end
  end
  return false
end

local function notification_contains(expected)
  for _, notification in ipairs(notifications) do
    if notification.message:find(expected, 1, true) then
      return true
    end
  end
  return false
end

local tests = {}

tests["encrypt uses argv and supports paths with spaces"] = function()
  local fake = create_fake_vault()
  local config = reset_config(fake)
  local buf = new_buffer({ "plain" })

  vault.encrypt(buf)

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
  end, "encrypt did not update target buffer")

  assert_true(log_contains(fake.log, "ARG:" .. config.password_file), "password path was not passed as one argv item")
  assert_false(log_contains(fake.log, "ARG:--encrypt-vault-id"), "default encryption must not force --encrypt-vault-id")
  assert_true(vim.b[buf].ansible_vault_encrypted, "encrypted buffer marker was not set")
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

  assert_eq(vim.api.nvim_buf_get_lines(second, 0, -1, false), { "second" }, "current buffer was modified by async callback")
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
  reset_config(fake, { password_file = false, vault_id = "prod@" .. pass, encrypt_vault_id = nil })

  local buf = new_buffer({ "plain" })
  vault.encrypt(buf)

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
  end, "encrypt with vault_id did not finish")

  assert_true(log_contains(fake.log, "ARG:prod@" .. pass), "vault_id was not passed")
  assert_false(log_contains(fake.log, "ARG:--encrypt-vault-id"), "encrypt_vault_id should be opt-in")

  reset_config(fake, { password_file = false, vault_id = "prod@" .. pass, encrypt_vault_id = "prod" })
  local other = new_buffer({ "plain" })
  vault.encrypt(other)

  wait_until(function()
    return vim.api.nvim_buf_get_lines(other, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
  end, "encrypt with explicit encrypt_vault_id did not finish")

  assert_true(log_contains(fake.log, "ARG:--encrypt-vault-id"), "explicit encrypt_vault_id flag was not passed")
  assert_true(log_has_line(fake.log, "ARG:prod"), "explicit encrypt_vault_id value was not passed")
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

tests["setup clears autodetect autocmd when disabled"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { auto_detect = true })
  reset_config(fake, { auto_detect = false })
  assert_eq(#vim.api.nvim_get_autocmds({ group = "AnsibleVault", event = "BufReadPost" }), 0, "autodetect autocmd was not cleared")
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
  assert_true(read_file(original_file):find("EXTERNAL CHANGE", 1, true), "external file content was overwritten")
  vim.api.nvim_buf_delete(edit_buf, { force = true })
end

tests["VaultEncryptString preserves YAML keys for full-line selections"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local buf = new_buffer({ "password: secret" })
  vim.fn.setpos("'<", { 0, 1, 1, 0 })
  vim.fn.setpos("'>", { 0, 1, #"password: secret", 0 })

  vault.encrypt_string()

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
  end, "YAML key was not preserved for full-line string encryption")

  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  assert_eq(lines[1], "password: !vault |", "full-line YAML output has wrong first line")
  assert_eq(lines[2], "          $ANSIBLE_VAULT;1.1;AES256", "full-line YAML output has wrong vault header")
end

tests["VaultEncryptString can replace only a YAML value"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local line = "password: secret"
  local buf = new_buffer({ line })
  vim.fn.setpos("'<", { 0, 1, 11, 0 })
  vim.fn.setpos("'>", { 0, 1, #line, 0 })

  vault.encrypt_string()

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
  end, "YAML value-only encryption did not produce a vault scalar")

  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  assert_eq(lines[1], "password: !vault |", "value-only YAML output has wrong first line")
  assert_eq(lines[2], "          $ANSIBLE_VAULT;1.1;AES256", "value-only YAML output has wrong vault header")
end

local failures = 0
for name, test in pairs(tests) do
  io.stdout:write("TEST ", name, "\n")
  local ok, err = xpcall(test, debug.traceback)
  if not ok then
    failures = failures + 1
    io.stderr:write("FAILED ", name, "\n", err, "\n")
  end
end

if failures > 0 then
  vim.cmd("cquit")
end

io.stdout:write("All tests passed\n")
vim.cmd("qa!")
