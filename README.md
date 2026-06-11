# ansible-vault.nvim

> **Warning**: This plugin is in early development stage. Use at your own risk and always backup your files before using encryption/decryption features.

A Neovim plugin for encrypting and decrypting files using Ansible Vault.

中文文档: [README.zh-CN.md](README.zh-CN.md)

## Features

- Encrypt/decrypt entire buffer
- View encrypted content in floating window (read-only)
- Encrypt selected text as inline YAML vault strings
- Encrypt, view, and decrypt inline vault strings under the cursor
- Toggle between encrypted/decrypted states
- Rekey encrypted files
- Diff decrypted vault content against another file or a Git revision
- Find vault files with Telescope or the built-in `vim.ui.select` picker
- Auto-detect vault-encrypted files
- Optionally auto-open encrypted files with `VaultEdit`
- Support for password file, one or more vault IDs, or interactive password input
- Optional in-memory cache for interactive passwords
- Per-command credential overrides with command-line completion
- `:checkhealth ansible-vault` diagnostics
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
      -- Optional: multiple vault IDs
      vault_ids = nil,
      -- Optional: vault ID label to use when encrypting
      encrypt_vault_id = nil,
      -- Optional: automatically open encrypted files with VaultEdit
      auto_edit = false,
      -- Optional: cache interactive passwords in memory for N seconds
      password_cache_ttl = 0,
      -- Optional: VaultFiles picker backend ("auto", "telescope", "builtin")
      picker = "auto",
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

  -- Multiple vault IDs. Takes precedence over vault_id when set.
  vault_ids = nil,

  -- Vault ID label to use for encryption.
  -- Leave nil to let ansible-vault choose from the configured vault IDs.
  encrypt_vault_id = nil,

  -- New password file for :VaultRekey
  rekey_password_file = nil,

  -- New vault ID for :VaultRekey, for example "prod@~/.ansible/new-pass"
  rekey_vault_id = nil,

  -- Auto detect vault encrypted files on BufReadPost
  auto_detect = true,

  -- Automatically open encrypted files with :VaultEdit after BufReadPost
  auto_edit = false,

  -- Cache interactive passwords in memory for N seconds.
  -- Set to 0 to prompt for every operation.
  password_cache_ttl = 0,

  -- Picker backend for :VaultFiles: "auto", "telescope", or "builtin"
  picker = "auto",

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
2. `vault_ids`
3. `vault_id`
4. interactive password prompt

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

Use `vault_ids` when more than one identity is needed:

```lua
require("ansible-vault").setup({
  vault_ids = {
    "dev@~/.ansible/dev-pass",
    "prod@~/.ansible/prod-pass",
  },
  encrypt_vault_id = "prod",
})
```

Leave `encrypt_vault_id = nil` if you want `ansible-vault` to choose the
encryption identity from the configured vault IDs.

Most commands also accept temporary credential overrides. These do not mutate
your global setup:

```vim
:VaultEdit --vault-id prod@~/.ansible/prod-pass
:VaultView --vault-password-file ~/.ansible/prod-pass
:VaultEncryptString prod
```

The bare label shortcut, such as `prod`, is supported by the inline encrypt
commands and maps to `--encrypt-vault-id prod`.

Configure `VaultRekey` with a new password file or a new vault ID:

```lua
require("ansible-vault").setup({
  password_file = "~/.ansible/old-pass",
  rekey_password_file = "~/.ansible/new-pass",
})
```

```lua
require("ansible-vault").setup({
  vault_id = "old@~/.ansible/old-pass",
  rekey_vault_id = "new@~/.ansible/new-pass",
})
```

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

Interactive passwords can be cached in Neovim memory for a short period:

```lua
require("ansible-vault").setup({
  password_cache_ttl = 300,
})
```

The cache is disabled by default. Clear it manually with
`:VaultClearPasswordCache`.

## Commands

| Command | Description |
|---------|-------------|
| `:VaultEncrypt` | Encrypt current buffer |
| `:VaultDecrypt` | Decrypt current buffer |
| `:VaultView` | View decrypted content in floating window |
| `:VaultEdit` | Edit encrypted file in a scratch buffer, encrypt on save |
| `:VaultClearPasswordCache` | Clear the in-memory interactive password cache |
| `:VaultDiff {file}` | Diff decrypted current buffer against another file |
| `:VaultDiff --git [ref]` | Diff decrypted current buffer against a Git revision |
| `:VaultFiles [view\|edit\|rekey]` | Pick a vault file and view, edit, or rekey it |
| `:VaultRekey [args]` | Rekey the current encrypted file |
| `:VaultToggle` | Toggle between encrypted/decrypted state |
| `:VaultEncryptString` | Encrypt selected text (visual mode) |
| `:VaultDecryptString` | Decrypt selected inline vault string in place |
| `:VaultViewString` | View selected encrypted string (visual mode) |
| `:VaultEncryptStringUnderCursor` | Encrypt the YAML value under the cursor |
| `:VaultViewStringUnderCursor` | View the inline vault block under the cursor |
| `:VaultDecryptStringUnderCursor` | Decrypt the inline vault block under the cursor |

## Health Check

Run:

```vim
:checkhealth ansible-vault
```

The health check verifies the configured executable, password file readability
and permissions, vault ID labels, `encrypt_vault_id`, and `VaultRekey` target
configuration.

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

### Automatically Edit Encrypted Files

Enable `auto_edit` if you want encrypted files to open directly in the safer
`:VaultEdit` scratch workflow:

```lua
require("ansible-vault").setup({
  auto_edit = true,
})
```

The original encrypted buffer is reloaded after save. The plugin suppresses the
automatic edit loop for that reload.

### Toggle a Buffer

Run `:VaultToggle` to encrypt a plain buffer or decrypt an encrypted buffer.
This is convenient for quick checks, but be careful not to save decrypted
secrets accidentally.

### Diff Decrypted Vault Content

Compare the current buffer with another vault file:

```vim
:VaultDiff ../group_vars/prod/vault.yml
```

Compare the current file with a Git revision:

```vim
:VaultDiff --git HEAD
:VaultDiff --git main
```

Both sides are decrypted into temporary nofile buffers before Neovim diff mode
is enabled. Plain files also work, so you can compare encrypted and decrypted
versions during migrations.

### Pick Vault Files

Run:

```vim
:VaultFiles view
:VaultFiles edit
:VaultFiles rekey
```

The picker scans files under the current working directory and keeps files whose
first line is an Ansible Vault header. Telescope is used automatically when it
is installed; otherwise the plugin falls back to `vim.ui.select`. Set
`picker = "builtin"` to always use the built-in picker.

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

### Decrypt an Inline YAML Vault String

Select a YAML vault block and run:

```vim
:VaultDecryptString
```

For example:

```yaml
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

is replaced with:

```yaml
password: secret
```

### Work With Inline Vault Strings Under Cursor

When the cursor is on a plain YAML key/value line, run:

```vim
:VaultEncryptStringUnderCursor
```

When the cursor is on a YAML `!vault |` block, run:

```vim
:VaultViewStringUnderCursor
:VaultDecryptStringUnderCursor
```

The plugin finds the surrounding vault block automatically, so you do not need
to select the block by hand.

### Rekey an Encrypted File

Configure a rekey target first:

```lua
require("ansible-vault").setup({
  password_file = "~/.ansible/old-pass",
  rekey_password_file = "~/.ansible/new-pass",
})
```

Then open an encrypted file and run:

```vim
:VaultRekey
```

You can also pass Ansible Vault rekey arguments directly:

```vim
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
:VaultRekey --new-vault-id prod@~/.ansible/prod-pass
```

The buffer must be file-backed, encrypted, and unmodified. After a successful
rekey, the plugin reloads the encrypted file.

## Keymaps

The plugin doesn't set any keymaps by default. You can add your own:

```lua
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", "<cmd>VaultRekey<cr>", { desc = "Vault Rekey" })
vim.keymap.set("n", "<leader>vD", "<cmd>VaultDiff --git HEAD<cr>", { desc = "Vault Diff" })
vim.keymap.set("n", "<leader>vf", "<cmd>VaultFiles view<cr>", { desc = "Vault Files" })
vim.keymap.set("n", "<leader>vt", "<cmd>VaultToggle<cr>", { desc = "Vault Toggle" })
vim.keymap.set("v", "<leader>vs", "<cmd>VaultEncryptString<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("v", "<leader>vS", "<cmd>VaultDecryptString<cr>", { desc = "Vault Decrypt String" })
vim.keymap.set("v", "<leader>vv", "<cmd>VaultViewString<cr>", { desc = "Vault View String" })
vim.keymap.set("n", "<leader>vs", "<cmd>VaultEncryptStringUnderCursor<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("n", "<leader>vS", "<cmd>VaultDecryptStringUnderCursor<cr>", { desc = "Vault Decrypt String" })
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

-- Rekey current encrypted file
vault.rekey()

-- Diff decrypted current buffer against a file or Git revision
vault.diff({ positionals = { "../other-vault.yml" } })
vault.diff({ git_ref = "HEAD" })

-- Pick vault files from the current working directory
vault.files({ positionals = { "view" } })

-- Clear the optional in-memory password cache
vault.clear_password_cache()

-- Toggle encryption state
vault.toggle()

-- Encrypt selected text
vault.encrypt_string()

-- Decrypt selected text
vault.decrypt_string()

-- View selected encrypted string in floating window
vault.view_string()

-- Cursor-based inline YAML helpers
vault.encrypt_string_under_cursor()
vault.view_string_under_cursor()
vault.decrypt_string_under_cursor()

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
- `password_cache_ttl` is disabled by default. When enabled, the interactive
  password is kept in Neovim process memory until it expires or
  `:VaultClearPasswordCache` is run.
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
