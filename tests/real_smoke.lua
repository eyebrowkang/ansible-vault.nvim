vim.opt.runtimepath:prepend(vim.fn.getcwd())

local vault = require("ansible-vault")

local ansible_vault = vim.env.ANSIBLE_VAULT_NVIM_REAL_BIN
if not ansible_vault or ansible_vault == "" then
  ansible_vault = vim.fn.getcwd() .. "/.venv/bin/ansible-vault"
end

if vim.fn.executable(ansible_vault) ~= 1 then
  error("real ansible-vault binary is not executable: " .. ansible_vault)
end

local function fail(message)
  error(message, 2)
end

local function assert_eq(actual, expected, message) -- luacheck: ignore 211
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

local function wait_until(predicate, message)
  if not vim.wait(8000, predicate, 20) then
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

local workdir = temp_dir()
local password_file = workdir .. "/vault-pass"
write_file(password_file, "secret\n")
vim.fn.setfperm(password_file, "rw-------")

vault.setup({
  ansible_vault_path = ansible_vault,
  password_file = password_file,
  auto_detect = false,
  notify_success = false,
})

local buf = vim.api.nvim_create_buf(true, false)
vim.api.nvim_set_current_buf(buf)
vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "plain: value" })

vault.encrypt(buf)
wait_until(function()
  return vault.is_buffer_encrypted(buf)
end, "real encrypt did not produce vault ciphertext")

vault.decrypt(buf)
wait_until(function()
  return vim.api.nvim_buf_get_lines(buf, 0, -1, false)[1] == "plain: value"
end, "real decrypt did not restore plaintext")

vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "password: secret" })
vault.encrypt_string({ line1 = 1, line2 = 1, range = 1 })
wait_until(function()
  return vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] == "password: !vault |"
end, "real encrypt_string did not produce inline vault YAML")

vault.decrypt_string({ line1 = 1, line2 = vim.api.nvim_buf_line_count(buf), range = 1 })
wait_until(function()
  return vim.api.nvim_buf_get_lines(buf, 0, -1, false)[1] == "password: secret"
end, "real decrypt_string did not restore inline plaintext")

local target_file = workdir .. "/target.yml"
write_file(target_file, "plain: target\n")
local target_buf = vim.api.nvim_create_buf(true, false)
vim.api.nvim_buf_set_name(target_buf, target_file)
vim.api.nvim_set_current_buf(target_buf)
vim.api.nvim_buf_set_lines(target_buf, 0, -1, false, { "plain: target" })
vault.encrypt(target_buf)
wait_until(function()
  return vault.is_buffer_encrypted(target_buf)
end, "real target encrypt did not finish")
vim.cmd("silent write!")

vim.api.nvim_set_current_buf(buf)
vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "plain: current" })
local tab_count = #vim.api.nvim_list_tabpages()
vault.diff({ positionals = { target_file } })
wait_until(function()
  return #vim.api.nvim_list_tabpages() > tab_count
end, "real VaultDiff did not open a diff tab")

local diff_contents = {}
for _, win in ipairs(vim.api.nvim_tabpage_list_wins(vim.api.nvim_get_current_tabpage())) do
  local lines = vim.api.nvim_buf_get_lines(vim.api.nvim_win_get_buf(win), 0, -1, false)
  table.insert(diff_contents, table.concat(lines, "\n"))
end
assert_true(vim.tbl_contains(diff_contents, "plain: current"), "real diff missed current plaintext")
assert_true(vim.tbl_contains(diff_contents, "plain: target"), "real diff missed target plaintext")
vim.cmd("tabclose!")

local edit_file = workdir .. "/edit.yml"
vim.cmd("edit " .. vim.fn.fnameescape(edit_file))
local file_buf = vim.api.nvim_get_current_buf()
vim.api.nvim_buf_set_lines(file_buf, 0, -1, false, { "plain: edit" })
vault.encrypt(file_buf)
wait_until(function()
  return vault.is_buffer_encrypted(file_buf)
end, "real file encrypt did not finish")
vim.cmd("silent write")
vim.bo[file_buf].modified = false

vault.edit(file_buf)
wait_until(function()
  return vim.bo[vim.api.nvim_get_current_buf()].buftype == "acwrite"
end, "real VaultEdit did not open scratch buffer")

local edit_buf = vim.api.nvim_get_current_buf()
vim.api.nvim_buf_set_lines(edit_buf, 0, -1, false, { "plain: edited" })
vim.cmd("silent write")
wait_until(function()
  return vim.api.nvim_get_current_buf() == file_buf
end, "real VaultEdit save did not restore original buffer")

assert_true(read_file(edit_file):match("^%$ANSIBLE_VAULT;1.1;AES256"), "real VaultEdit did not write ciphertext")

vault.decrypt(file_buf)
wait_until(function()
  return vim.api.nvim_buf_get_lines(file_buf, 0, -1, false)[1] == "plain: edited"
end, "real VaultEdit ciphertext did not decrypt to saved content")

--- The four behaviours that only the real binary can prove -----------------

-- 1. A decrypted, file-backed buffer writes ciphertext and nothing else.
local live_file = workdir .. "/live.yml"
write_file(live_file, "")
vim.cmd("edit " .. vim.fn.fnameescape(live_file))
local live_buf = vim.api.nvim_get_current_buf()
vim.api.nvim_buf_set_lines(live_buf, 0, -1, false, { "api_key: SUPERSECRET" })
vault.encrypt(live_buf)
wait_until(function()
  return vault.is_buffer_encrypted(live_buf)
end, "real encrypt of the live buffer did not finish")
vim.cmd("silent write")

vault.decrypt(live_buf)
wait_until(function()
  return vim.api.nvim_buf_get_lines(live_buf, 0, 1, false)[1] == "api_key: SUPERSECRET"
end, "real decrypt of the live buffer did not finish")

assert_true(vim.bo[live_buf].swapfile == false, "decrypted buffer still has 'swapfile' on")
assert_true(vim.bo[live_buf].undofile == false, "decrypted buffer still has 'undofile' on")
assert_eq(vim.bo[live_buf].buftype, "acwrite", "decrypted buffer does not route writes through the plugin")
assert_eq(vim.fn.swapname(live_buf), "", "decrypted buffer has a swap file")

vim.api.nvim_buf_set_lines(live_buf, 0, -1, false, { "api_key: EVENMORESECRET" })
vim.cmd("silent write")

local live_contents = read_file(live_file)
assert_true(live_contents:match("^%$ANSIBLE_VAULT"), "writing a decrypted buffer did not produce ciphertext")
assert_true(
  live_contents:find("EVENMORESECRET", 1, true) == nil,
  "plaintext reached disk when writing a decrypted buffer"
)

-- 2. A 1.2 header keeps its vault id label across a decrypt/encrypt round trip.
local labelled = workdir .. "/labelled.yml"
local label_pass = workdir .. "/prod-pass"
write_file(label_pass, "prodsecret\n")
vim.fn.setfperm(label_pass, "rw-------")
write_file(labelled, "plain: labelled\n")
vim.fn.system({ ansible_vault, "encrypt", "--vault-id", "prod@" .. label_pass, labelled })
assert_true(
  read_file(labelled):match("^%$ANSIBLE_VAULT;1%.2;AES256;prod") ~= nil,
  "fixture was not encrypted with a 1.2 vault id label"
)

vault.setup({
  ansible_vault_path = ansible_vault,
  vault_ids = { "prod@" .. label_pass },
  auto_detect = false,
  notify_success = false,
})

vim.cmd("edit " .. vim.fn.fnameescape(labelled))
local label_buf = vim.api.nvim_get_current_buf()
vault.decrypt(label_buf)
wait_until(function()
  return vim.api.nvim_buf_get_lines(label_buf, 0, 1, false)[1] == "plain: labelled"
end, "real decrypt of the labelled file did not finish")

vim.cmd("silent write")
assert_eq(
  read_file(labelled):match("^[^\n]*"),
  "$ANSIBLE_VAULT;1.2;AES256;prod",
  "re-encrypting downgraded the file to 1.1 and dropped its vault id label"
)

-- 3. ansible.cfg alone is enough; adding our own flag on top is what breaks
--    encryption with "The vault-ids default,default are available to encrypt".
local project = workdir .. "/project"
vim.fn.mkdir(project .. "/group_vars/prod", "p")
write_file(project .. "/.vault_pass", "cfgsecret\n")
vim.fn.setfperm(project .. "/.vault_pass", "rw-------")
write_file(project .. "/ansible.cfg", "[defaults]\nvault_password_file = .vault_pass\n")

vault.setup({
  ansible_vault_path = ansible_vault,
  auto_detect = false,
  notify_success = false,
})
require("ansible-vault.ansible_cfg").clear_cache()

local cfg_file = project .. "/group_vars/prod/vault.yml"
write_file(cfg_file, "")
vim.cmd("edit " .. vim.fn.fnameescape(cfg_file))
local cfg_buf = vim.api.nvim_get_current_buf()
vim.api.nvim_buf_set_lines(cfg_buf, 0, -1, false, { "db_password: fromcfg" })
vault.encrypt(cfg_buf)
wait_until(function()
  return vault.is_buffer_encrypted(cfg_buf)
end, "encrypting with ansible.cfg credentials failed")

vault.decrypt(cfg_buf)
wait_until(function()
  return vim.api.nvim_buf_get_lines(cfg_buf, 0, 1, false)[1] == "db_password: fromcfg"
end, "decrypting with ansible.cfg credentials failed")

-- 4. VaultCreate produces a file that only ever contained ciphertext.
local created = workdir .. "/created.yml"
vault.setup({
  ansible_vault_path = ansible_vault,
  password_file = password_file,
  auto_detect = false,
  notify_success = false,
})
vim.cmd("VaultCreate " .. vim.fn.fnameescape(created))
local created_buf = vim.api.nvim_get_current_buf()
assert_eq(vim.fn.filereadable(created), 0, "VaultCreate created the file before it was written")
vim.api.nvim_buf_set_lines(created_buf, 0, -1, false, { "brand: new" })
vim.cmd("silent write")
wait_until(function()
  return vim.fn.filereadable(created) == 1
end, "VaultCreate write did not produce a file")
assert_true(read_file(created):match("^%$ANSIBLE_VAULT"), "VaultCreate did not write ciphertext")

io.stdout:write("REAL_SMOKE_OK\n")
