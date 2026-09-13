---Health diagnostics must describe credentials without creating them.
---@param H table
---@param tests table
return function(H, tests)
  local eq, yes = H.assert_eq, H.assert_true

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

  ---Both of Ansible's asking sources name a password the user types, not a file
  ---to read, so neither can be "not readable".
  tests["checkhealth does not report an asking vault id as unreadable"] = function()
    local fake = H.create_fake_vault()
    local script = H.temp_dir() .. "/health_prompt.lua"
    H.write_file(
      script,
      string.format(
        [[
vim.opt.runtimepath:prepend(%q)
require('ansible-vault').setup({
  ansible_vault_path = %q,
  vault_ids = { 'prod@prompt', 'dev@prompt_ask_vault_pass' },
  encrypt_vault_id = 'prod',
})
vim.cmd('checkhealth ansible-vault')
local report = table.concat(vim.api.nvim_buf_get_lines(0, 0, -1, false), '\n')
assert(report:find('Configured vault IDs: 2', 1, true), report)
assert(not report:find('not readable', 1, true), report)
io.stdout:write('HEALTH_OK\n'); io.stdout:flush()
]],
        H.root,
        fake.path
      )
    )
    local result = vim.system({ vim.v.progpath, "--headless", "-u", "NONE", "-l", script }):wait(20000)
    eq(result.code, 0, result.stdout .. result.stderr)
    yes(result.stdout:find("HEALTH_OK", 1, true))
  end
end
