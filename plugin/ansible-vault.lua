if vim.g.loaded_ansible_vault then
  return
end
vim.g.loaded_ansible_vault = true

-- Commands are declared in one place, `require("ansible-vault").register_commands()`.
-- Registering them here as well means they exist before `setup()` is called; each
-- one applies the configured defaults on first use, so calling `setup()` is
-- optional.
require("ansible-vault").register_commands()
