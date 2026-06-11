# ansible-vault.nvim

> **Warning**: This plugin is in early development stage. Use at your own risk and always backup your files before using encryption/decryption features.

A Neovim plugin for encrypting and decrypting files using Ansible Vault.

中文文档: [README.zh-CN.md](README.zh-CN.md)

## Features

- Encrypt/decrypt entire buffer
- View encrypted content in floating window (read-only)
- Encrypt selected text as inline YAML vault strings
- Toggle between encrypted/decrypted states
- Auto-detect vault-encrypted files
- Support for password file, vault ID, or interactive password input
- Conda environment support via `conda run`
- Statusline integration

## Requirements

- Neovim >= 0.9.0
- `ansible-vault` command available in PATH (or via conda environment)

## Installation

### lazy.nvim

```lua
{
  "eyebrowkang/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup({
      -- Optional: path to password file
      password_file = "~/.vault_pass",
      -- Optional: vault ID
      vault_id = nil,
      -- Optional: vault ID label to use when encrypting
      encrypt_vault_id = nil,
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
  "eyebrowkang/ansible-vault.nvim",
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

  -- Vault ID label to use for encryption.
  -- Leave nil to let ansible-vault choose from the configured vault IDs.
  encrypt_vault_id = nil,

  -- Auto detect vault encrypted files on BufReadPost
  auto_detect = true,

  -- Conda environment name where ansible-vault is installed.
  -- The plugin runs: conda run -n <env> ansible-vault ...
  conda_env = nil,

  -- Custom path to ansible-vault executable
  ansible_vault_path = nil,

  -- Enable debug logging (prints to :messages)
  debug = false,
})
```

### Password Sources

The plugin resolves credentials in this order:

1. `password_file`
2. `vault_id`
3. interactive password prompt

Use `password_file` for a single vault password:

```lua
require("ansible-vault").setup({
  password_file = "~/.ansible/vault-pass",
})
```

Use `vault_id` for Ansible multi-vault setups:

```lua
require("ansible-vault").setup({
  vault_id = "prod@~/.ansible/prod-pass",
  encrypt_vault_id = "prod",
})
```

Leave `encrypt_vault_id = nil` if you want `ansible-vault` to choose the
encryption identity from the configured vault IDs.

If `ansible-vault` is not on `PATH`, point to the executable directly:

```lua
require("ansible-vault").setup({
  ansible_vault_path = "/opt/homebrew/bin/ansible-vault",
  password_file = "~/.ansible/vault-pass",
})
```

If `ansible-vault` is installed inside a Conda environment:

```lua
require("ansible-vault").setup({
  conda_env = "ansible-dev",
  password_file = "~/.ansible/vault-pass",
})
```

## Commands

| Command | Description |
|---------|-------------|
| `:VaultEncrypt` | Encrypt current buffer |
| `:VaultDecrypt` | Decrypt current buffer |
| `:VaultView` | View decrypted content in floating window |
| `:VaultEdit` | Edit encrypted file in a scratch buffer, encrypt on save |
| `:VaultToggle` | Toggle between encrypted/decrypted state |
| `:VaultEncryptString` | Encrypt selected text (visual mode) |
| `:VaultViewString` | View selected encrypted string (visual mode) |

## Usage

### Encrypt a Plain File

1. Open a plain YAML or text file.
2. Run `:VaultEncrypt`.
3. Save the buffer with `:write`.

The buffer content is replaced with Ansible Vault ciphertext. The plugin does
not write the file automatically after `:VaultEncrypt`, so you can inspect the
result before saving.

### Decrypt an Encrypted File in Place

1. Open a file that starts with `$ANSIBLE_VAULT`.
2. Run `:VaultDecrypt`.
3. Edit the decrypted buffer.
4. Run `:VaultEncrypt` again before saving if the file should remain encrypted.

This workflow is simple, but the decrypted content lives in the original buffer.
For safer editing, prefer `:VaultEdit`.

### View an Encrypted File Without Modifying It

Run `:VaultView` on an encrypted buffer. The decrypted content opens in a
read-only floating window. Press `q` or `<Esc>` to close it.

### Edit an Encrypted File Safely

Run `:VaultEdit` on a file-backed encrypted buffer.

The plugin opens decrypted content in a scratch buffer with swap and persistent
undo disabled. When you run `:write` from that scratch buffer, the content is
encrypted and written back to the original file. The scratch buffer is then
closed and the original encrypted file is reloaded.

If the original file changed on disk while the scratch buffer was open, the save
is refused to avoid overwriting someone else's changes.

### Toggle a Buffer

Run `:VaultToggle` to encrypt a plain buffer or decrypt an encrypted buffer.
This is convenient for quick checks, but be careful not to save decrypted
secrets accidentally.

### Encrypt an Inline YAML String

Select text in visual mode and run:

```vim
:VaultEncryptString
```

For a full YAML line:

```yaml
password: secret
```

the plugin keeps the key and encrypts only the value:

```yaml
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

You can also select only the value in `password: secret`; the plugin still
inserts the encrypted value under the same YAML key.

### View an Inline YAML Vault String

Select a YAML vault block and run:

```vim
:VaultViewString
```

The decrypted value opens in a read-only floating window. Press `q` or `<Esc>`
to close it.

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

-- Edit encrypted buffer in a no-swap scratch buffer
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

## Inline YAML Strings

`VaultEncryptString` uses `ansible-vault encrypt_string --stdin-name`.
When the selection is a full YAML key/value line such as:

```yaml
password: secret
```

the plugin encrypts only the value and keeps the original key:

```yaml
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

When only the value is selected in `password: secret`, the replacement is also
inserted as the value for `password`.

## Security Notes

- Commands are executed as argv lists, not shell strings, so paths with spaces
  are supported and configuration values are not evaluated by a shell.
- Interactive passwords are collected with `inputsecret()` and written to a
  temporary `0600` password file for the duration of the vault operation.
- `VaultEdit` keeps the decrypted content in a scratch `acwrite` buffer with
  `swapfile=false`, `undofile=false`, and `bufhidden=wipe`.
- `VaultEdit` writes encrypted output through a temporary file in the same
  directory and then atomically replaces the original file.
- `VaultEdit` refuses to overwrite the original file if it changed on disk while
  the scratch buffer was open.
- Decrypted text is still present in Neovim process memory while viewing or
  editing. Review your Neovim plugins, clipboard settings, backups, shada, and
  terminal/session recording if you work with highly sensitive secrets.

## Development

Run the headless test suite:

```sh
make test
```

The tests use a fake `ansible-vault` executable, so they do not require Ansible
to be installed.

## License

MIT
