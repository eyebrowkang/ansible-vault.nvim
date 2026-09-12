---Shared test harness: the fake `ansible-vault`, the fixtures, and the
---assertions. Separated from the specs so adding a test does not mean scrolling
---past 250 lines of scaffolding, and so the spec files stay a flat list of cases.
local M = {}

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
new_label=""
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
    --new-vault-id)
      shift
      new_label="${1%%@*}"
      ;;
    --vault-id|--vault-password-file|--new-vault-password-file)
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
    # Mirror ansible-vault: the NEW identity decides the envelope, so a labelled
    # --new-vault-id produces a 1.2 header carrying that label.
    if [ -n "$new_label" ] && [ "$new_label" != "default" ]; then
      printf '$ANSIBLE_VAULT;1.2;AES256;%s\nREKEYED\n' "$new_label" > "$file_arg"
    else
      printf '$ANSIBLE_VAULT;1.1;AES256\nREKEYED\n' > "$file_arg"
    fi
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

  -- `setup()` below replaces the whole table, so there is nothing to clear by
  -- hand. Listing every key here is what made this drift out of sync with the
  -- schema every time one was added or removed.
  require("ansible-vault.cli").timeout_ms = 30000
  notifications = {}

  local config = {
    ansible_vault_path = fake.path,
  }

  if not opts or opts.password_files ~= false then
    config.password_files = opts and opts.password_files or make_password_file(fake.dir)
  end

  for key, value in pairs(opts or {}) do
    if not (key == "password_files" and value == false) then
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

local function make_project(cfg_lines)
  local root = temp_dir()
  vim.fn.mkdir(root .. "/group_vars/prod", "p")
  write_file(root .. "/.vault_pass", "cfgsecret\n")
  vim.fn.setfperm(root .. "/.vault_pass", "rw-------")
  write_file(root .. "/ansible.cfg", table.concat(cfg_lines, "\n") .. "\n")
  return root
end

M.assert_eq = assert_eq
M.assert_true = assert_true
M.assert_false = assert_false
M.wait_until = wait_until
M.write_file = write_file
M.read_file = read_file
M.temp_dir = temp_dir
M.create_fake_vault = create_fake_vault
M.make_password_file = make_password_file
M.reset_config = reset_config
M.make_project = make_project
M.new_file_buffer = new_file_buffer
M.new_buffer = new_buffer
M.log_contains = log_contains
M.log_has_line = log_has_line
M.notification_contains = notification_contains

return M
