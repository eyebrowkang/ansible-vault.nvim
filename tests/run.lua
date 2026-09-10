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
    fail(
      string.format(
        "%s\nexpected: %s\nactual:   %s",
        message or "values are not equal",
        vim.inspect(expected),
        vim.inspect(actual)
      )
    )
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

  write_file(
    path,
    [=[
#!/bin/sh
if [ -n "$FAKE_VAULT_LOG" ]; then
  printf 'CALL\n' >> "$FAKE_VAULT_LOG"
  printf 'CWD:%s\n' "$(pwd)" >> "$FAKE_VAULT_LOG"
  if [ -n "${ANSIBLE_VAULT_NVIM_PASSWORD+x}" ]; then
    printf 'ENVPW:set\n' >> "$FAKE_VAULT_LOG"
  fi
  for arg in "$@"; do
    printf 'ARG:%s\n' "$arg" >> "$FAKE_VAULT_LOG"
  done
fi

if [ -n "$FAKE_VAULT_FAIL" ]; then
  printf 'fake vault error: %s\n' "$FAKE_VAULT_FAIL" >&2
  exit 1
fi

action="$1"
shift
name="encrypted_string"
file_arg=""
label=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stdin-name)
      shift
      name="$1"
      ;;
    --encrypt-vault-id)
      shift
      label="$1"
      ;;
    --vault-id|--vault-password-file|--new-vault-id|--new-vault-password-file)
      shift
      ;;
    *)
      file_arg="$1"
      ;;
  esac
  shift || break
done

# Mirror ansible-vault: naming a non-default identity produces a 1.2 header
# carrying that label, anything else stays on 1.1.
if [ -n "$label" ] && [ "$label" != "default" ]; then
  header=$(printf '$ANSIBLE_VAULT;1.2;AES256;%s' "$label")
else
  header=$(printf '$ANSIBLE_VAULT;1.1;AES256')
fi

input=""
if [ "$action" != "rekey" ]; then
  input=$(cat)
fi
if [ -n "$FAKE_VAULT_SLEEP" ]; then
  sleep "$FAKE_VAULT_SLEEP"
fi
if [ -n "$FAKE_VAULT_STDIN_LOG" ]; then
  printf '%s' "$input" > "$FAKE_VAULT_STDIN_LOG"
fi

case "$action" in
  encrypt)
    printf '%s\n' "$header"
    printf 'ENC:%s\n' "$input"
    ;;
  decrypt)
    case "$input" in
      *EDITME*) printf 'plain: old\n' ;;
      *TARGET*) printf 'plain: target\n' ;;
      *ENCSTR:*) printf '%s\n' "${input##*ENCSTR:}" ;;
      *) printf 'plain: value\n' ;;
    esac
    ;;
  encrypt_string)
    printf '%s: !vault |\n' "$name"
    printf '          %s\n' "$header"
    printf '          ENCSTR:%s\n' "$input"
    ;;
  rekey)
    if [ -z "$file_arg" ]; then
      printf 'missing file arg\n' >&2
      exit 2
    fi
    printf '$ANSIBLE_VAULT;1.1;AES256\nREKEYED\n' > "$file_arg"
    ;;
  *)
    printf 'unknown action: %s\n' "$action" >&2
    exit 2
    ;;
esac
]=]
  )
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
  vim.env.FAKE_VAULT_FAIL = nil
  vim.env.FAKE_VAULT_SLEEP = nil
  vim.env.FAKE_VAULT_STDIN_LOG = nil
  vim.env.ANSIBLE_CONFIG = nil
  vim.env.ANSIBLE_VAULT_PASSWORD_FILE = nil
  vim.env.ANSIBLE_VAULT_IDENTITY_LIST = nil
  vim.env.ANSIBLE_VAULT_IDENTITY = nil
  vim.env.ANSIBLE_VAULT_ENCRYPT_IDENTITY = nil
  vim.env.ANSIBLE_VAULT_ID_MATCH = nil

  vault.config.password_file = nil
  vault.config.vault_id = nil
  vault.config.vault_ids = nil
  vault.config.encrypt_vault_id = nil
  vault.config.rekey_password_file = nil
  vault.config.rekey_vault_id = nil
  vault.config.auto_detect = true
  vault.config.auto_edit = false
  vault.config.password_cache_ttl = 0
  vault.config.picker = "auto"
  vault.config.timeout_ms = 30000
  vault.config.notify_success = true
  vault.config.conda_env = nil
  vault.config.ansible_vault_path = nil
  vault.config.debug = false
  vault.clear_password_cache()
  notifications = {}

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

---A file-backed buffer, which is what the plaintext-mode paths operate on.
local function new_file_buffer(dir, name, lines)
  local path = dir .. "/" .. name
  write_file(path, table.concat(lines, "\n") .. "\n")
  vim.cmd("edit " .. vim.fn.fnameescape(path))
  local buf = vim.api.nvim_get_current_buf()
  vim.bo[buf].modified = false
  return buf, path
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
    password_file = false,
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

tests["setup clears autodetect autocmd when disabled"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { auto_detect = true })
  reset_config(fake, { auto_detect = false })
  assert_eq(
    #vim.api.nvim_get_autocmds({ group = "AnsibleVault", event = "BufReadPost" }),
    0,
    "autodetect autocmd was not cleared"
  )
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

tests["command args can override encrypt vault id"] = function()
  local fake = create_fake_vault()
  local dev_pass = make_password_file(fake.dir)
  local prod_pass = make_password_file(fake.dir)
  reset_config(fake, {
    password_file = false,
    vault_ids = { "dev@" .. dev_pass, "prod@" .. prod_pass },
  })

  local line = "password: secret"
  local buf = new_buffer({ line })
  vim.fn.setpos("'<", { 0, 1, 1, 0 })
  vim.fn.setpos("'>", { 0, 1, #line, 0 })

  vim.cmd("VaultEncryptString prod")

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
  end, "VaultEncryptString command arg did not encrypt")

  assert_true(log_contains(fake.log, "ARG:--encrypt-vault-id"), "shortcut encrypt vault id flag was not passed")
  assert_true(log_has_line(fake.log, "ARG:prod"), "shortcut encrypt vault id value was not passed")
end

tests["command vault-id override replaces configured password file"] = function()
  local fake = create_fake_vault()
  local old_pass = fake.dir .. "/old-pass"
  local prod_pass = fake.dir .. "/prod-pass"
  write_file(old_pass, "old\n")
  write_file(prod_pass, "prod\n")

  reset_config(fake, { password_file = old_pass })

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
    password_file = false,
    vault_ids = { "prod@" .. prod_pass },
  })

  local label_completion = vim.fn.getcompletion("VaultEncryptString p", "cmdline")
  assert_true(vim.tbl_contains(label_completion, "prod"), "inline encrypt label was not completed")

  local flag_completion = vim.fn.getcompletion("VaultEdit --vault", "cmdline")
  assert_true(vim.tbl_contains(flag_completion, "--vault-id"), "vault-id flag was not completed")
  assert_true(vim.tbl_contains(flag_completion, "--vault-password-file"), "vault-password-file flag was not completed")
end

tests["interactive password cache avoids repeated prompts"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { password_file = false, password_cache_ttl = 60 })

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
  end, "first cached-password encrypt did not finish")

  local second = new_buffer({ "second" })
  vault.encrypt(second)
  wait_until(function()
    return vim.api.nvim_buf_get_lines(second, 0, 1, false)[1] == "$ANSIBLE_VAULT;1.1;AES256"
  end, "second cached-password encrypt did not finish")

  vim.fn.inputsecret = original_inputsecret
  assert_eq(prompt_count, 1, "password prompt should have been cached")
end

tests["notify_success false suppresses success notifications"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { notify_success = false })

  local buf = new_buffer({ "plain: value" })
  vault.encrypt(buf)

  wait_until(function()
    return vault.is_buffer_encrypted(buf)
  end, "encrypt did not finish with notify_success disabled")

  assert_false(notification_contains("Buffer encrypted successfully"), "success notification was not suppressed")
end

tests["slow vault operations time out"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { timeout_ms = 50 })
  vim.env.FAKE_VAULT_SLEEP = "1"

  local buf = new_buffer({ "plain: value" })
  vault.encrypt(buf)

  wait_until(function()
    return notification_contains("timed out")
  end, "slow vault operation did not time out")

  assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "plain: value" }, "timed out operation changed buffer")
  vim.env.FAKE_VAULT_SLEEP = nil
end

tests["VaultInfo reports state and operations emit User events"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local event_data
  vim.api.nvim_create_autocmd("User", {
    pattern = "AnsibleVaultEncrypt",
    once = true,
    callback = function(event)
      event_data = event.data
    end,
  })

  local buf = new_buffer({ "plain: value" })
  vault.encrypt(buf)

  wait_until(function()
    return vault.is_buffer_encrypted(buf)
  end, "encrypt did not finish before VaultInfo check")

  assert_true(event_data and event_data.operation == "Encrypt", "encrypt User event was not emitted")

  local info = table.concat(vault.get_info(buf), "\n")
  assert_true(info:find("Encrypted: yes", 1, true), "VaultInfo did not report encrypted state")
  assert_true(info:find("Credential source: password_file", 1, true), "VaultInfo did not report credential source")
  assert_true(info:find("Last operation: Encrypt", 1, true), "VaultInfo did not report last operation")
end

tests["VaultDecryptString replaces selected YAML vault block"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local buf = new_buffer({
    "password: !vault |",
    "          $ANSIBLE_VAULT;1.1;AES256",
    "          ENCSTR:secret",
  })
  vim.fn.setpos("'<", { 0, 1, 1, 0 })
  vim.fn.setpos("'>", { 0, 3, #"          ENCSTR:secret", 0 })

  vault.decrypt_string()

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: secret"
  end, "selected YAML vault block was not decrypted")

  assert_eq(vim.api.nvim_buf_get_lines(buf, 0, -1, false), { "password: secret" })
end

tests["VaultDiff refuses to run when Neovim would use an external diff"] = function()
  local stays = vault._private.diff_stays_in_memory

  -- Read from the raw option string. `vim.opt.diffopt:get()` returns a list of
  -- "key:value" strings on some releases and a map on others, and reading the
  -- wrong shape here silently disables VaultDiff.
  local diffopt, diffexpr = vim.o.diffopt, vim.o.diffexpr

  vim.o.diffexpr = ""
  vim.o.diffopt = "internal,filler,closeoff,indent-heuristic,inline:char,linematch:40"
  assert_true(stays(), "the default diffopt keeps the diff in memory")

  vim.o.diffopt = "filler,closeoff"
  assert_false(stays(), 'without "internal" Neovim writes both sides to temporary files')

  vim.o.diffopt = "internal,filler"
  vim.o.diffexpr = "MyDiff()"
  assert_false(stays(), "a diffexpr makes Neovim write both sides to temporary files")

  vim.o.diffopt = diffopt
  vim.o.diffexpr = diffexpr
end

tests["VaultDiff opens decrypted diff buffers"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local target_file = fake.dir .. "/target.yml"
  write_file(target_file, "$ANSIBLE_VAULT;1.1;AES256\nTARGET\n")

  local buf = new_buffer({ "$ANSIBLE_VAULT;1.1;AES256", "EDITME" })
  vim.bo[buf].filetype = "yaml"
  local tab_count = #vim.api.nvim_list_tabpages()

  vault.diff({ positionals = { target_file } })

  wait_until(function()
    return #vim.api.nvim_list_tabpages() > tab_count
  end, "VaultDiff did not open a diff tab")

  local tab = vim.api.nvim_get_current_tabpage()
  local contents = {}
  for _, win in ipairs(vim.api.nvim_tabpage_list_wins(tab)) do
    local lines = vim.api.nvim_buf_get_lines(vim.api.nvim_win_get_buf(win), 0, -1, false)
    table.insert(contents, table.concat(lines, "\n"))
  end

  assert_true(vim.tbl_contains(contents, "plain: old"), "current decrypted content was not in diff")
  assert_true(vim.tbl_contains(contents, "plain: target"), "target decrypted content was not in diff")
  vim.cmd("tabclose!")
end

tests["auto_edit opens encrypted files in a scratch buffer"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { auto_edit = true })

  local original_file = fake.dir .. "/auto-edit.yml"
  write_file(original_file, "$ANSIBLE_VAULT;1.1;AES256\nEDITME\n")

  vim.cmd("edit " .. vim.fn.fnameescape(original_file))
  local original_buf = vim.api.nvim_get_current_buf()

  wait_until(function()
    return vim.api.nvim_get_current_buf() ~= original_buf
      and vim.bo[vim.api.nvim_get_current_buf()].buftype == "acwrite"
  end, "auto_edit did not open VaultEdit scratch buffer")

  vim.api.nvim_buf_delete(vim.api.nvim_get_current_buf(), { force = true })
end

tests["VaultFiles builtin picker can view selected vault file"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { picker = "builtin" })

  local original_cwd = vim.fn.getcwd()
  local original_select = vim.ui.select
  local vault_file = fake.dir .. "/picked.yml"
  write_file(vault_file, "$ANSIBLE_VAULT;1.1;AES256\nTARGET\n")

  vim.fn.chdir(fake.dir)
  vim.ui.select = function(items, _, callback)
    assert_eq(items, { "picked.yml" }, "VaultFiles did not discover the expected vault file")
    callback(items[1])
  end

  vault.files({ positionals = { "view" } })

  wait_until(function()
    return vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false)[1] == "plain: target"
  end, "VaultFiles did not view the selected vault file")

  vim.ui.select = original_select
  vim.fn.chdir(original_cwd)
  vim.api.nvim_win_close(0, true)
end

tests["VaultFiles edit suppresses auto_edit duplicate scratch buffers"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { picker = "builtin", auto_edit = true })

  local original_cwd = vim.fn.getcwd()
  local original_select = vim.ui.select
  local vault_file = fake.dir .. "/picked.yml"
  write_file(vault_file, "$ANSIBLE_VAULT;1.1;AES256\nTARGET\n")

  vim.fn.chdir(fake.dir)
  vim.ui.select = function(items, _, callback)
    assert_eq(items, { "picked.yml" }, "VaultFiles did not discover the expected vault file")
    callback(items[1])
  end

  vault.files({ positionals = { "edit" } })

  wait_until(function()
    return vim.bo[vim.api.nvim_get_current_buf()].buftype == "acwrite"
  end, "VaultFiles edit did not open a scratch buffer")

  vim.wait(100, function()
    return false
  end, 20)

  local scratch_count = 0
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if
      vim.api.nvim_buf_is_loaded(buf)
      and vim.bo[buf].buftype == "acwrite"
      and vim.api.nvim_buf_get_name(buf):find("picked.yml", 1, true)
    then
      scratch_count = scratch_count + 1
    end
  end

  assert_eq(scratch_count, 1, "VaultFiles edit opened duplicate scratch buffers")

  vim.ui.select = original_select
  vim.fn.chdir(original_cwd)
  vim.api.nvim_buf_delete(vim.api.nvim_get_current_buf(), { force = true })
end

tests["under cursor commands encrypt view and decrypt YAML vault strings"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local buf = new_buffer({ "password: secret" })
  vim.api.nvim_win_set_cursor(0, { 1, 0 })
  vault.encrypt_string_under_cursor()

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
  end, "under-cursor YAML value was not encrypted")

  vim.api.nvim_win_set_cursor(0, { 2, 10 })
  vault.view_string_under_cursor()

  wait_until(function()
    return vim.api.nvim_get_current_buf() ~= buf
  end, "under-cursor vault view did not open")

  assert_eq(vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false), { "secret" })

  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_win_set_cursor(0, { 2, 10 })
  vault.decrypt_string_under_cursor()

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
  vault.view_string_under_cursor()

  assert_eq(vim.api.nvim_get_current_buf(), buf, "view should not open for a cursor outside the vault block")
  assert_true(notification_contains("No text selected"), "missing warning for cursor outside a vault block")
end

tests["VaultRekey rekeys a file-backed encrypted buffer"] = function()
  local fake = create_fake_vault()
  local new_pass = make_password_file(fake.dir)
  reset_config(fake, { rekey_password_file = new_pass })

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

tests["B5 wrong password clears cache"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { password_file = false, password_cache_ttl = 60 })

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
  vim.fn.setpos("'<", { 0, 1, 1, 0 })
  vim.fn.setpos("'>", { 0, 1, #'password: "sec#ret" # prod', 0 })

  vault.encrypt_string()

  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
  end, "YAML value with comment was not encrypted")

  assert_eq(read_file(stdin_log), "sec#ret", "YAML comments or quoted # were included in the encrypted value")
end

tests["B11 blockwise string encryption preserves unselected columns"] = function()
  local fake = create_fake_vault()
  reset_config(fake)
  local stdin_log = fake.dir .. "/stdin.log"
  vim.env.FAKE_VAULT_STDIN_LOG = stdin_log

  local buf = new_buffer({ "abcdef", "ghijkl", "mnopqr" })
  local ctrl_v = vim.api.nvim_replace_termcodes("<C-v>", true, false, true)
  vim.cmd("normal! gg0l" .. ctrl_v .. "jjll")
  vim.cmd("normal! \27")
  vim.fn.setpos("'<", { 0, 1, 2, 0 })
  vim.fn.setpos("'>", { 0, 3, 4, 0 })

  vault.encrypt_string({ line1 = 1, line2 = 3, range = 3 })

  wait_until(function()
    return vim.b[buf].ansible_vault_pending == nil
  end, "blockwise string encryption did not finish")

  assert_eq(read_file(stdin_log), "bcd\nhij\nnop", "blockwise selection did not send the selected rectangle")

  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  assert_eq(lines[1], "aencrypted_string: !vault |ef", "first blockwise line did not preserve outside columns")
  assert_eq(lines[2], "g          $ANSIBLE_VAULT;1.1;AES256kl", "middle blockwise line lost outside columns")
  assert_eq(lines[3], "m          ENCSTR:bcdqr", "last selected blockwise line lost outside columns")
end

tests["B6 decrypt string quotes YAML special values"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local function quote(s)
    return vault._private.yaml_quote_value(s)
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

  vault.view_string_under_cursor()

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

  vault.setup({})
  assert_eq(vault.config.encrypt_vault_id, nil, "encrypt_vault_id should reset to nil on re-setup")
  assert_eq(vault.config.notify_success, true, "default value should be restored")
end

tests["B9 command args support quoted paths with spaces"] = function()
  local fake = create_fake_vault()
  local pass_path = fake.dir .. "/path with spaces/vault pass"
  vim.fn.mkdir(fake.dir .. "/path with spaces", "p")
  write_file(pass_path, "secret\n")
  vim.fn.setfperm(pass_path, "rw-------")
  reset_config(fake, { password_file = false })

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
  reset_config(fake, { password_file = false })

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
  assert_true(vim.b[buf].ansible_vault_encrypted, "buffer should be marked encrypted")
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
  vault.decrypt_string_under_cursor()

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
  vault.decrypt_string_under_cursor()
  wait_until(function()
    return vim.api.nvim_buf_get_lines(buf, 4, 5, false)[1] == "second: beta"
  end, "second value was not decrypted")

  vim.api.nvim_win_set_cursor(0, { 1, 0 })
  vault.decrypt_string_under_cursor()
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
  vault.decrypt_string_under_cursor()
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
  local redact = vault._private.redact_argv
  assert_eq(
    redact({ "ansible-vault", "encrypt", "--vault-password-file", "/home/u/.secret", "-" }),
    "ansible-vault encrypt --vault-password-file <redacted> -"
  )
  assert_eq(
    redact({ "ansible-vault", "encrypt", "--vault-id", "prod@/home/u/.secret", "--encrypt-vault-id", "prod" }),
    "ansible-vault encrypt --vault-id <redacted> --encrypt-vault-id prod"
  )
end

--- Inline YAML shapes ------------------------------------------------------

tests["inline parser handles every shape ansible accepts"] = function()
  local parse = vault._private.parse_vault_from_yaml
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
  local parse = vault._private.parse_vault_from_yaml
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
  vault.decrypt_string_under_cursor()

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

  -- BufReadPost records the label; auto_detect is off in tests, so do it here.
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

tests["statusline reports the vault id label"] = function()
  local fake = create_fake_vault()
  reset_config(fake)

  local dir = temp_dir()
  local buf = new_file_buffer(dir, "vault.yml", { "$ANSIBLE_VAULT;1.2;AES256;prod", "ENC:x" })

  vault.view(buf) -- any operation records the header
  wait_until(function()
    return vim.b[buf].ansible_vault_label == "prod"
  end, "label was not recorded")

  assert_eq(vault.status(buf), "[VAULT:prod]", "an encrypted buffer should show its vault id label")

  vault.decrypt(buf)
  wait_until(function()
    return vim.bo[buf].buftype == "acwrite"
  end, "buffer did not enter plaintext mode")

  assert_eq(vault.status(buf), "[VAULT:decrypted]", "a decrypted buffer should say so")
end

--- ansible.cfg and ANSIBLE_* ----------------------------------------------

local function make_project(cfg_lines)
  local root = temp_dir()
  vim.fn.mkdir(root .. "/group_vars/prod", "p")
  write_file(root .. "/.vault_pass", "cfgsecret\n")
  vim.fn.setfperm(root .. "/.vault_pass", "rw-------")
  write_file(root .. "/ansible.cfg", table.concat(cfg_lines, "\n") .. "\n")
  return root
end

tests["ansible.cfg found upward supplies credentials without extra flags"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { password_file = false })

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

  local info = table.concat(vault.get_info(buf), "\n")
  assert_true(info:find("ansible.cfg", 1, true) ~= nil, "VaultInfo should report the discovered config")
end

tests["configured credentials name an identity when ansible.cfg adds one"] = function()
  local fake = create_fake_vault()
  local root = make_project({ "[defaults]", "vault_password_file = .vault_pass" })
  local own_pass = make_password_file(fake.dir)
  reset_config(fake, { password_file = own_pass })

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
  reset_config(fake, { password_file = false })

  local root = make_project({ "[defaults]", "vault_password_file = .vault_pass" })
  local env_pass = make_password_file(fake.dir)
  vim.env.ANSIBLE_VAULT_PASSWORD_FILE = env_pass

  local buf = new_file_buffer(root .. "/group_vars/prod", "vault.yml", { "plain" })
  local info = table.concat(vault.get_info(buf), "\n")
  assert_true(
    info:find("ANSIBLE_* environment", 1, true) ~= nil,
    "VaultInfo should attribute credentials to the environment"
  )

  vim.env.ANSIBLE_VAULT_PASSWORD_FILE = nil
end

tests["ansible.cfg relative paths resolve against the config directory"] = function()
  local fake = create_fake_vault()
  reset_config(fake, { password_file = false })

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
  reset_config(fake, { password_file = false, vault_ids = { "dev@" .. dev, "prod@" .. prod } })

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
  reset_config(fake, { password_file = false })

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
