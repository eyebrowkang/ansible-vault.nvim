# ansible-vault.nvim

> **Warning**: This plugin is in early development stage. Use at your own risk and always backup your files before using encryption/decryption features.

A Neovim plugin for encrypting and decrypting files using Ansible Vault.

## Features

- Encrypt/decrypt entire buffer
- View encrypted content in floating window (read-only)
- Encrypt selected text (inline vault strings)
- Toggle between encrypted/decrypted states
- Auto-detect vault-encrypted files
- Support for password file, vault ID, or interactive password input
- Conda environment support
- Statusline integration

## Requirements

- Neovim >= 0.9.0
- `ansible-vault` command available in PATH (or via conda environment)

## Installation

### lazy.nvim

```lua
{
  "your-username/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup({
      -- Optional: path to password file
      password_file = "~/.vault_pass",
      -- Optional: vault ID
      vault_id = nil,
      -- Optional: auto detect encrypted files (default: true)
      auto_detect = true,
      -- Optional: conda environment name
      conda_env = "ansible-dev",
      -- Optional: custom ansible-vault path
      ansible_vault_path = nil,
    })
  end,
}
```

### packer.nvim

```lua
use {
  "your-username/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup()
  end,
}
```

## Configuration

```lua
require("ansible-vault").setup({
  -- Path to ansible-vault password file
  password_file = nil,

  -- Vault ID to use for decryption (for multi-vault setups)
  vault_id = nil,

  -- Vault ID to use for encryption (default: "default")
  -- Required when multiple vault IDs are configured
  encrypt_vault_id = "default",

  -- Auto detect vault encrypted files on BufReadPost
  auto_detect = true,

  -- Conda environment name where ansible-vault is installed
  conda_env = nil,

  -- Custom path to ansible-vault executable
  ansible_vault_path = nil,

  -- Enable debug logging (prints to :messages)
  debug = false,
})
```

## Commands

| Command | Description |
|---------|-------------|
| `:VaultEncrypt` | Encrypt current buffer |
| `:VaultDecrypt` | Decrypt current buffer |
| `:VaultView` | View decrypted content in floating window |
| `:VaultEdit` | Edit encrypted file in memory buffer, auto-encrypt on save |
| `:VaultToggle` | Toggle between encrypted/decrypted state |
| `:VaultEncryptString` | Encrypt selected text (visual mode) |
| `:VaultViewString` | View selected encrypted string (visual mode) |

## Keymaps

The plugin doesn't set any keymaps by default. You can add your own:

```lua
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vt", "<cmd>VaultToggle<cr>", { desc = "Vault Toggle" })
vim.keymap.set("v", "<leader>vs", "<cmd>VaultEncryptString<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("v", "<leader>vv", "<cmd>VaultViewString<cr>", { desc = "Vault View String" })
```

## Statusline Integration

You can show vault status in your statusline:

```lua
-- For lualine
require("lualine").setup({
  sections = {
    lualine_x = {
      { require("ansible-vault").status },
    },
  },
})

-- Manual check
if require("ansible-vault").is_buffer_encrypted() then
  -- buffer is encrypted
end
```

## API

```lua
local vault = require("ansible-vault")

-- Check if content is encrypted
vault.is_encrypted(content)  -- string or table of lines

-- Check if current buffer is encrypted
vault.is_buffer_encrypted()

-- Encrypt current buffer
vault.encrypt()

-- Decrypt current buffer
vault.decrypt()

-- View encrypted buffer in floating window
vault.view()

-- Edit encrypted buffer in memory (no temp file, auto-encrypt on save)
vault.edit()

-- Toggle encryption state
vault.toggle()

-- Encrypt selected text
vault.encrypt_string()

-- View selected encrypted string in floating window
vault.view_string()

-- Get status string for statusline
vault.status()
```

## License

MIT
