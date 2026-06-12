if vim.g.loaded_ansible_vault then
  return
end
vim.g.loaded_ansible_vault = true

local function ensure_setup()
  local vault = require("ansible-vault")
  if not vault._configured then
    vault.setup(vim.g.ansible_vault_config or {})
  end
  return vault
end

local function comp_opts(arg_lead)
  return ensure_setup()._private.complete_operation_args(arg_lead)
end

local function comp_opts_labels(arg_lead)
  return ensure_setup()._private.complete_operation_args(arg_lead, false, true)
end

local function comp_opts_rekey(arg_lead)
  return ensure_setup()._private.complete_operation_args(arg_lead, true)
end

local function comp_diff(arg_lead)
  return ensure_setup()._private.complete_diff_args(arg_lead)
end

local function comp_files(arg_lead)
  return ensure_setup()._private.complete_files_args(arg_lead)
end

vim.api.nvim_create_user_command("VaultEncrypt", function(cmd_opts)
  local vault = ensure_setup()
  vault.encrypt(nil, vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "Encrypt current buffer with ansible-vault",
  force = true,
})

vim.api.nvim_create_user_command("VaultDecrypt", function(cmd_opts)
  local vault = ensure_setup()
  vault.decrypt(nil, vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "Decrypt current buffer with ansible-vault",
  force = true,
})

vim.api.nvim_create_user_command("VaultView", function(cmd_opts)
  local vault = ensure_setup()
  vault.view(nil, vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "View encrypted buffer in floating window",
  force = true,
})

vim.api.nvim_create_user_command("VaultToggle", function(cmd_opts)
  local vault = ensure_setup()
  vault.toggle(nil, vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "Toggle vault encryption state",
  force = true,
})

vim.api.nvim_create_user_command("VaultEdit", function(cmd_opts)
  local vault = ensure_setup()
  vault.edit(nil, vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "Edit encrypted buffer in a secure scratch buffer",
  force = true,
})

vim.api.nvim_create_user_command("VaultClearPasswordCache", function()
  local vault = ensure_setup()
  vault.clear_password_cache()
end, { desc = "Clear cached Ansible Vault password", force = true })

vim.api.nvim_create_user_command("VaultDiff", function(cmd_opts)
  local vault = ensure_setup()
  vault.diff(vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_diff,
  desc = "Diff decrypted vault content",
  force = true,
})

vim.api.nvim_create_user_command("VaultFiles", function(cmd_opts)
  local vault = ensure_setup()
  vault.files(vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_files,
  desc = "Pick an Ansible Vault file",
  force = true,
})

vim.api.nvim_create_user_command("VaultInfo", function(cmd_opts)
  local vault = ensure_setup()
  vault.info(nil, vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts_rekey,
  desc = "Show Ansible Vault buffer and configuration info",
  force = true,
})

vim.api.nvim_create_user_command("VaultRekey", function(cmd_opts)
  local vault = ensure_setup()
  vault.rekey(vault._parse_command_options(cmd_opts.args, { rekey = true }))
end, {
  nargs = "*",
  complete = comp_opts_rekey,
  desc = "Rekey encrypted file with ansible-vault",
  force = true,
})

vim.api.nvim_create_user_command("VaultEncryptString", function(cmd_opts)
  local vault = ensure_setup()
  vault.encrypt_string(
    cmd_opts,
    vault._parse_command_options(cmd_opts.args, { label_shortcut = true })
  )
end, {
  range = true,
  nargs = "*",
  complete = comp_opts_labels,
  desc = "Encrypt selected string",
  force = true,
})

vim.api.nvim_create_user_command("VaultDecryptString", function(cmd_opts)
  local vault = ensure_setup()
  vault.decrypt_string(cmd_opts, vault._parse_command_options(cmd_opts.args))
end, {
  range = true,
  nargs = "*",
  complete = comp_opts,
  desc = "Decrypt selected string",
  force = true,
})

vim.api.nvim_create_user_command("VaultViewString", function(cmd_opts)
  local vault = ensure_setup()
  vault.view_string(cmd_opts, vault._parse_command_options(cmd_opts.args))
end, {
  range = true,
  nargs = "*",
  complete = comp_opts,
  desc = "View selected encrypted string",
  force = true,
})

vim.api.nvim_create_user_command("VaultEncryptStringUnderCursor", function(cmd_opts)
  local vault = ensure_setup()
  vault.encrypt_string_under_cursor(
    vault._parse_command_options(cmd_opts.args, { label_shortcut = true })
  )
end, {
  nargs = "*",
  complete = comp_opts_labels,
  desc = "Encrypt YAML value under cursor",
  force = true,
})

vim.api.nvim_create_user_command("VaultViewStringUnderCursor", function(cmd_opts)
  local vault = ensure_setup()
  vault.view_string_under_cursor(vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "View vault string under cursor",
  force = true,
})

vim.api.nvim_create_user_command("VaultDecryptStringUnderCursor", function(cmd_opts)
  local vault = ensure_setup()
  vault.decrypt_string_under_cursor(vault._parse_command_options(cmd_opts.args))
end, {
  nargs = "*",
  complete = comp_opts,
  desc = "Decrypt vault string under cursor",
  force = true,
})
