if vim.g.loaded_ansible_vault then
  return
end
vim.g.loaded_ansible_vault = true

-- Loading the module registers the commands, so they exist without `setup()`
-- and there is nothing to keep in sync here.
require("ansible-vault")
