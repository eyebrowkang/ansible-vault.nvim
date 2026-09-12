---Shared command-level harness.
---
---Public behaviour is driven through the six user commands, because that is the
---only interface the plugin has; pure internal functions are required directly.
---
---`ansible-vault` is replaced by a byte-exact Python double (`fake_vault.py`)
---that really consumes the credentials it is handed and really verifies them, so
---"the command succeeded" here means the credential plumbing worked. It is not a
---cryptographic or precedence oracle: actual Ansible behaviour is checked against
---the real binary in `real_smoke.lua`.
local H = { root = vim.fn.getcwd() }
local notifications, patches, sabotages = {}, {}, {}
local vault = require("ansible-vault")

function H.assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error(
      (message or "values differ") .. "\nexpected: " .. vim.inspect(expected) .. "\nactual: " .. vim.inspect(actual),
      2
    )
  end
end

function H.assert_true(value, message)
  if not value then
    error(message or "expected truthy value", 2)
  end
end

function H.assert_false(value, message)
  H.assert_true(not value, message or "expected false value")
end

function H.wait_until(predicate, message, timeout)
  if not vim.wait(timeout or 5000, predicate, 10) then
    error((message or "timed out") .. "\nnotifications: " .. vim.inspect(notifications), 2)
  end
end

function H.write_file(path, contents)
  local file = assert(io.open(path, "wb"))
  assert(file:write(contents))
  assert(file:close())
end

function H.read_file(path)
  local file = assert(io.open(path, "rb"))
  local contents = file:read("*a")
  assert(file:close())
  return contents
end

function H.temp_dir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

---Every file under `dir`, so a test can prove nothing new appeared.
---@param dir string
---@return string[]
function H.files_under(dir)
  local found = vim.fn.glob(dir .. "/**/*", true, true)
  local files = {}
  for _, path in ipairs(found) do
    if vim.fn.isdirectory(path) == 0 then
      table.insert(files, path)
    end
  end
  table.sort(files)
  return files
end

---Files under `dir` whose bytes contain `needle`.
---@param dir string
---@param needle string
---@return string[]
function H.grep_under(dir, needle)
  local hits = {}
  for _, path in ipairs(H.files_under(dir)) do
    local ok, contents = pcall(H.read_file, path)
    if ok and contents:find(needle, 1, true) then
      table.insert(hits, path)
    end
  end
  return hits
end

---The fake lives at a path containing a space on purpose: an executable or
---credential path that is not one argv item is a real bug this catches for free.
function H.create_fake_vault()
  local dir = H.temp_dir()
  local path = dir .. "/fake vault"
  H.write_file(path, H.read_file(H.root .. "/tests/fake_vault.py"))
  vim.fn.setfperm(path, "rwx------")
  return { dir = dir, path = path, log = dir .. "/vault.log" }
end

function H.make_password_file(base, value, name)
  vim.fn.mkdir(base .. "/dir with space", "p")
  local path = base .. "/dir with space/" .. (name or "pass file")
  H.write_file(path, (value or "secret") .. "\n")
  vim.fn.setfperm(path, "rw-------")
  return path
end

---Point the plugin at the fake and start from a known credential state.
---
---Every `ANSIBLE_*` variable is cleared first: the real environment must not
---decide what a test resolves. Operation-only keys (`ask_password`,
---`new_*`) are deliberately NOT accepted here — `setup()` rejects them, which is
---itself asserted in spec_credentials.
function H.reset_config(fake, opts)
  notifications = {}
  for key in pairs(vim.fn.environ()) do
    if key:match("^FAKE_VAULT_") or key:match("^ANSIBLE_") then
      vim.env[key] = nil
    end
  end
  vim.env.FAKE_VAULT_LOG = fake.log
  require("ansible-vault.cli").timeout_ms = 30000
  require("ansible-vault.ansible_cfg").clear_cache()
  local config = { ansible_vault_path = fake.path }
  if not opts or opts.password_files ~= false then
    config.password_files = opts and opts.password_files or H.make_password_file(fake.dir)
  end
  for key, value in pairs(opts or {}) do
    if not (key == "password_files" and value == false) then
      config[key] = value
    end
  end
  vault.setup(config)
  return config
end

function H.new_buffer(lines)
  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modified = false
  return buf
end

function H.open_file(path)
  vim.cmd("silent edit " .. vim.fn.fnameescape(path))
  return vim.api.nvim_get_current_buf()
end

function H.new_file_buffer(dir, name, lines)
  local path = dir .. "/" .. name
  H.write_file(path, table.concat(lines, "\n") .. "\n")
  return H.open_file(path), path
end

function H.lines(buf)
  return vim.api.nvim_buf_get_lines(buf or 0, 0, -1, false)
end

function H.text(buf)
  return table.concat(H.lines(buf), "\n")
end

function H.encrypted(buf)
  return (H.lines(buf)[1] or ""):match("^%$ANSIBLE_VAULT;") ~= nil
end

function H.hex(bytes)
  return (bytes:gsub(".", function(char)
    return string.format("%02x", char:byte())
  end))
end

---Build an envelope the fake can open, sealed with `password`.
---
---Written here rather than obtained by running the encrypt path, so a fixture is
---never produced by the same code a test is checking.
function H.envelope(value, password, label)
  local header = label and ("$ANSIBLE_VAULT;1.2;AES256;" .. label) or "$ANSIBLE_VAULT;1.1;AES256"
  local payload = vim.json.encode({ value = H.hex(value), password = vim.fn.sha256(password or "secret"), nonce = 0 })
  return { header, H.hex(payload) }
end

---The same envelope as one indented `key: !vault |` block.
function H.inline(value, prefix, password, label)
  local result = { (prefix or "password:") .. " !vault |" }
  local indent = (prefix or ""):match("^%s*") or ""
  for _, line in ipairs(H.envelope(value, password, label)) do
    table.insert(result, indent .. "          " .. line)
  end
  return result
end

function H.log_contains(path, text)
  return vim.fn.filereadable(path) == 1 and H.read_file(path):find(text, 1, true) ~= nil
end

function H.log_has_line(path, expected)
  if vim.fn.filereadable(path) == 0 then
    return false
  end
  for line in H.read_file(path):gmatch("[^\n]+") do
    if line == expected then
      return true
    end
  end
  return false
end

function H.log_lines(path)
  local lines = {}
  if vim.fn.filereadable(path) == 1 then
    for line in H.read_file(path):gmatch("[^\n]+") do
      table.insert(lines, line)
    end
  end
  return lines
end

function H.calls(fake, action)
  local count = 0
  for _, line in ipairs(H.log_lines(fake.log)) do
    if line == (action and ("ACTION:" .. action) or "CALL") then
      count = count + 1
    end
  end
  return count
end

function H.notification_contains(text)
  for _, item in ipairs(notifications) do
    if tostring(item.message):lower():find(text:lower(), 1, true) then
      return true
    end
  end
  return false
end

---Everything the user was told this test, as one string. Used to prove a secret
---is absent rather than that a message is present.
function H.notification_text()
  local parts = {}
  for _, item in ipairs(notifications) do
    table.insert(parts, tostring(item.message))
  end
  return table.concat(parts, "\n")
end

function H.notified_error()
  for _, item in ipairs(notifications) do
    if item.level == vim.log.levels.ERROR or item.level == vim.log.levels.WARN then
      return true
    end
  end
  return false
end

function H.clear_notifications()
  notifications = {}
end

---A command that must report failure, either as an Ex error or a notification.
function H.command_fails(command)
  H.clear_notifications()
  local ok = pcall(vim.cmd, command)
  H.wait_until(function()
    return not ok or H.notified_error()
  end, "command did not report failure: " .. command)
end

---A `:w` that must fail as an Ex error, returning the message it failed with.
---
---A `BufWriteCmd` that only notifies is reported to Neovim as a successful
---write, and `:wq` would then quit with the changes unsaved. That is why this
---asserts on the Ex error and not on a message — and why the reason a write
---failed has to be read back from here rather than from `vim.notify`.
---@param command? string
---@return string message
function H.write_fails(command)
  local ok, err = pcall(vim.cmd, command or "silent write")
  H.assert_false(ok, "failed write must raise an Ex error, not only notify")
  return tostring(err)
end

function H.open_scratch(command, source)
  source = source or vim.api.nvim_get_current_buf()
  vim.cmd(command or "VaultEdit")
  H.wait_until(function()
    return vim.api.nvim_get_current_buf() ~= source
  end, "scratch did not open")
  return vim.api.nvim_get_current_buf()
end

function H.assert_hardened(buf)
  H.assert_false(vim.bo[buf].swapfile, "plaintext swapfile must be disabled")
  H.assert_false(vim.bo[buf].undofile, "plaintext undofile must be disabled")
  H.assert_eq(vim.fn.swapname(buf), "", "plaintext must have no swap file")
end

function H.patch(object, key, replacement)
  table.insert(patches, { object = object, key = key, original = object[key] })
  object[key] = replacement
end

---Register an autocmd that fights the plugin, so a failure path can be reached.
---
---Torn down by `H.run` however the test ends. Doing this inline would leave a
---global `OptionSet` handler behind on the first assertion failure, and every
---later test would then be running against a sabotaged editor.
---@param events string|string[]
---@param opts table
---@return integer id
function H.sabotage(events, opts)
  local id = vim.api.nvim_create_autocmd(events, opts)
  table.insert(sabotages, id)
  return id
end

---Answer the same credential question an operation asks, synchronously.
---
---`resolve` only defers when it has to prompt, so this is the honest way to
---assert on the argv and environment the child would be given without also
---asserting on whatever the fake happened to do with them.
function H.resolve_credentials(opts, context)
  local result, called = nil, false
  require("ansible-vault.credentials").resolve(
    require("ansible-vault.config").effective(opts),
    context or {},
    function(creds)
      result, called = creds, true
    end
  )
  H.assert_true(called, "credential resolution did not answer synchronously")
  return result
end

function H.make_project(cfg_lines)
  local root = H.temp_dir()
  vim.fn.mkdir(root .. "/group_vars/prod", "p")
  H.write_file(root .. "/.vault_pass", "cfgsecret\n")
  vim.fn.setfperm(root .. "/.vault_pass", "rw-------")
  H.write_file(root .. "/ansible.cfg", table.concat(cfg_lines, "\n") .. "\n")
  return root
end

---Where the interactive password helper is installed, so a test can delete it and
---force the fail-closed path to be taken again.
function H.askpass_path()
  local base = vim.fn.stdpath("run")
  return base .. "/ansible-vault.nvim/askpass.sh", base .. "/ansible-vault.nvim"
end

---Run each case with restoration even when an assertion fails. No test can
---leave a mocked inputsecret, a patched timeout or a live session for its
---neighbour, and the specs are run in sorted order so an order-dependent flake
---cannot hide behind `pairs()`.
function H.run(test)
  local env = vim.fn.environ()
  local options = {}
  for _, key in ipairs({
    "hidden",
    "updatecount",
    "undofile",
    "swapfile",
    "backup",
    "writebackup",
    "directory",
    "undodir",
    "backupdir",
  }) do
    options[key] = vim.o[key]
  end
  local cwd = vim.fn.getcwd()
  vim.o.hidden = true
  H.patch(vim, "notify", function(message, level)
    table.insert(notifications, { message = message, level = level })
  end)
  local ok, err = xpcall(test, debug.traceback)
  -- Destroy sessions before letting scheduled callbacks drain.
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
  end
  for index = #patches, 1, -1 do
    local patch = patches[index]
    patch.object[patch.key] = patch.original
  end
  patches = {}
  for _, id in ipairs(sabotages) do
    pcall(vim.api.nvim_del_autocmd, id)
  end
  sabotages = {}
  vim.wait(50, function()
    return false
  end, 10)
  for key in pairs(vim.fn.environ()) do
    if env[key] == nil then
      vim.env[key] = nil
    end
  end
  for key, value in pairs(env) do
    vim.env[key] = value
  end
  for key, value in pairs(options) do
    vim.o[key] = value
  end
  vim.cmd("cd " .. vim.fn.fnameescape(cwd))
  return ok, err
end

return H
