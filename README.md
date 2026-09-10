# ansible-vault.nvim

A Neovim plugin for working with Ansible Vault files and inline `!vault` YAML
values, built so that decrypted content never reaches the disk.

中文文档: [README.zh-CN.md](README.zh-CN.md)

## Features

**Privacy**

- Decrypted buffers disable `'swapfile'` and `'undofile'` *before* the plaintext
  arrives, so nothing survives a crash
- Every write is routed through the plugin, which means `:w` re-encrypts instead
  of writing plaintext, and Neovim makes no backup or undo file
- Interactive passwords are passed to `ansible-vault` through its environment;
  no secret is ever written to disk
- Process output is never echoed into error messages

**Vault operations**

- Encrypt, decrypt, view and edit whole files
- Create a new encrypted file with `:VaultCreate`
- Encrypt, view and decrypt inline `!vault` values, by selection or under the cursor
- Rekey encrypted files
- Diff decrypted vault content against another file or a Git revision
- Find vault files with Telescope or the built-in `vim.ui.select` picker

**Credentials**

- Reads `ansible.cfg` and the `ANSIBLE_*` environment variables the way Ansible
  does, searching upward from the current file
- Password file, one or more vault IDs, or an interactive prompt
- Per-command credential overrides with command-line completion
- Optional in-memory cache for interactive passwords

**Fidelity**

- Preserves the vault ID label in a `1.2` header instead of silently rewriting
  the file as `1.1`
- Handles every inline shape Ansible accepts: `|`, `|-`, `>`, `|2`, quoted keys,
  list items and arbitrary nesting

**Integration**

- `:VaultInfo` buffer and configuration diagnostics
- `:checkhealth ansible-vault`
- `User` autocmd events for statuslines and other plugins
- Statusline helper that shows the vault ID label
- Conda environment support via `conda run`

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
      -- Optional: ansible-vault job timeout in milliseconds (0 disables it)
      timeout_ms = 30000,
      -- Optional: suppress success/info notifications
      notify_success = true,
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

  -- ansible-vault job timeout in milliseconds. Set 0 to disable.
  timeout_ms = 30000,

  -- Show success/info notifications after completed operations
  notify_success = true,

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

1. per-command overrides, such as `:VaultEncrypt --vault-id prod@~/.prod-pass`
2. `setup()` configuration: `password_file`, then `vault_ids`, then `vault_id`
3. `ANSIBLE_*` environment variables
4. `ansible.cfg`
5. interactive password prompt

Layers 3 and 4 are Ansible's own. When credentials come from there the plugin
passes no credential flags at all and simply runs `ansible-vault` in the right
directory, letting it resolve them. This matters: passing `--vault-password-file`
on top of an `ansible.cfg` that already sets one makes `ansible-vault encrypt`
fail with `The vault-ids default,default are available to encrypt`.

#### ansible.cfg discovery

Ansible only looks for `ansible.cfg` in the process working directory and does
not search upward. In an editor the working directory is rarely the playbook
directory, so this plugin walks up from the current file instead:

1. `$ANSIBLE_CONFIG` (a file, or a directory containing `ansible.cfg`)
2. `ansible.cfg` or `.ansible.cfg`, searching upward from the current file
3. `~/.ansible.cfg`
4. `/etc/ansible/ansible.cfg`

`ansible-vault` is then run with its working directory set to wherever the
config was found, so relative paths inside it resolve exactly as Ansible
resolves them, which is relative to the config file itself.

These keys are read from `[defaults]`, and the matching environment variables
override them: `vault_password_file`, `vault_identity_list`, `vault_identity`,
`vault_encrypt_identity`, `vault_id_match` and `ask_vault_pass`.

Run `:VaultInfo` to see which config was found and which credential source is
actually in effect.

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

#### Vault ID labels are preserved

A file encrypted with a vault ID carries the label in its header:

```
$ANSIBLE_VAULT;1.2;AES256;prod
```

Re-encrypting such a file with a plain `--vault-password-file` would rewrite it
as `$ANSIBLE_VAULT;1.1;AES256` and drop the label. The plugin reads the label
before decrypting and names it again on the way back, so `:VaultEdit`,
`:VaultDecrypt` + `:w` and `:VaultRekey` all leave the header intact.

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
| `:VaultDecrypt` | Decrypt current buffer for editing; `:w` re-encrypts |
| `:VaultCreate {file}` | Create a new encrypted file (`!` overwrites) |
| `:VaultView` | View decrypted content in floating window |
| `:VaultEdit` | Edit encrypted file in a scratch buffer, encrypt on save |
| `:VaultClearPasswordCache` | Clear the in-memory interactive password cache |
| `:VaultDiff {file}` | Diff decrypted current buffer against another file |
| `:VaultDiff --git [ref]` | Diff decrypted current buffer against a Git revision |
| `:VaultFiles [view\|edit\|rekey]` | Pick a vault file and view, edit, or rekey it |
| `:VaultInfo [args]` | Show current buffer and plugin configuration diagnostics |
| `:VaultRekey [args]` | Rekey the current encrypted file |
| `:VaultToggle` | Toggle between encrypted/decrypted state |
| `:VaultEncryptString` | Encrypt selected text (visual mode) |
| `:VaultDecryptString` | Decrypt selected inline vault string in place; `:w` restores it |
| `:VaultViewString` | View selected encrypted string (visual mode) |
| `:VaultEncryptStringUnderCursor` | Encrypt the YAML value under the cursor |
| `:VaultViewStringUnderCursor` | View the inline vault block under the cursor |
| `:VaultDecryptStringUnderCursor` | Decrypt the inline vault block under the cursor |

## Health Check

Run:

```vim
:checkhealth ansible-vault
```

The health check reports:

- the configured executable, including the `conda run` wrapper
- which credential source is actually in effect, resolved through the same code
  the real operations use
- the `ansible.cfg` that was found, how it was found, and the directory
  `ansible-vault` will run in
- password file readability and permissions, recognising executable password
  scripts as the supported configuration they are
- vault ID labels, `encrypt_vault_id`, and the `VaultRekey` target
- whether interactive passwords can be kept off disk entirely
- global options that could still persist decrypted content, such as `'shada'`

## Usage

### Encrypt a Plain File

1. Open a plain YAML or text file.
2. Run `:VaultEncrypt`.
3. Save the buffer with `:write`.

The buffer content is replaced with Ansible Vault ciphertext. The plugin does
not write the file automatically after `:VaultEncrypt`, so you can inspect the
result before saving.

### Decrypt a File for Editing

1. Open a file that starts with `$ANSIBLE_VAULT`.
2. Run `:VaultDecrypt`.
3. Edit the decrypted buffer.
4. Run `:write`.

`:VaultDecrypt` puts the buffer into **plaintext editing mode**. The buffer
shows the decrypted content, but the file on disk only ever holds ciphertext:

- `'swapfile'` and `'undofile'` are turned off before the plaintext arrives, and
  any swap file that already existed is deleted
- `'buftype'` becomes `acwrite`, so `:w`, `:wq`, `:x` and even
  `:w some-other-file` are all handled by the plugin, which encrypts first
- because Neovim never runs its own write path, no backup file is created and no
  undo file is written

The buffer stays decrypted after a write so you can keep editing. Run
`:VaultEncrypt` to turn it back into ciphertext and restore normal buffer
behaviour, or `:edit!` to reload the encrypted file.

`:VaultEdit` remains available and does the same thing in a separate scratch
buffer, leaving the original buffer untouched.

### Create a New Encrypted File

```vim
:VaultCreate group_vars/prod/vault.yml
```

This opens an empty, hardened buffer. The file is not created until you run
`:write`, and it is only ever written encrypted. Use `:VaultCreate!` to replace
an existing file.

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

Enable `auto_edit` if you want encrypted files to open directly in the
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
Decrypting this way enters the same plaintext editing mode as `:VaultDecrypt`,
so `:w` still re-encrypts.

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

### Inspect State

Run:

```vim
:VaultInfo
```

The info window shows the current buffer state, credential source, configured
vault labels, auto-edit/picker settings, timeout, password-cache state, and the
last successful vault operation.

### Tune Notifications and Timeouts

By default, vault jobs time out after 30 seconds. Set `timeout_ms = 0` to
disable the timeout, or lower it for tighter feedback:

```lua
require("ansible-vault").setup({
  timeout_ms = 10000,
  notify_success = false,
})
```

Errors and warnings are still shown when `notify_success = false`; only
successful informational messages are suppressed.

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

The buffer enters **inline plaintext mode**: the decrypted value is tracked, the
buffer is hardened the same way as for whole-file decryption, and `:w` folds the
value back into a `!vault` block before writing. Surrounding lines are written
unchanged, so this works on files that are only partly encrypted.

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
vim.keymap.set("n", "<leader>vc", "<cmd>VaultCreate<cr>", { desc = "Vault Create" })
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", "<cmd>VaultRekey<cr>", { desc = "Vault Rekey" })
vim.keymap.set("n", "<leader>vD", "<cmd>VaultDiff --git HEAD<cr>", { desc = "Vault Diff" })
vim.keymap.set("n", "<leader>vf", "<cmd>VaultFiles view<cr>", { desc = "Vault Files" })
vim.keymap.set("n", "<leader>vt", "<cmd>VaultToggle<cr>", { desc = "Vault Toggle" })
vim.keymap.set("v", "<leader>vs", ":VaultEncryptString<cr>", { silent = true, desc = "Vault Encrypt String" })
vim.keymap.set("v", "<leader>vS", ":VaultDecryptString<cr>", { silent = true, desc = "Vault Decrypt String" })
vim.keymap.set("v", "<leader>vv", ":VaultViewString<cr>", { silent = true, desc = "Vault View String" })
vim.keymap.set("n", "<leader>vs", "<cmd>VaultEncryptStringUnderCursor<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("n", "<leader>vS", "<cmd>VaultDecryptStringUnderCursor<cr>", { desc = "Vault Decrypt String" })
```

## Statusline Integration

You can show vault status in your statusline:

The status string is `"[VAULT]"` for an encrypted buffer, `"[VAULT:prod]"` when
the file carries a vault ID label, `"[VAULT:decrypted]"` while it is in plaintext
editing mode, and `""` otherwise.

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

-- Parse a $ANSIBLE_VAULT header -> { version, cipher, label } or nil
vault.parse_header(content)

-- Check if current buffer is encrypted
vault.is_buffer_encrypted()

-- Create a new encrypted file
vault.create({ positionals = { "group_vars/prod/vault.yml" } })

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

-- Show current buffer and plugin state
vault.info()
local info_lines = vault.get_info()

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

-- Get status string for statusline: "", "[VAULT]", "[VAULT:prod]" or
-- "[VAULT:decrypted]"
vault.status()

-- Drop every secret this process still holds (also runs on VimLeavePre)
vault.cleanup()
```

## User Events

The plugin emits `User` autocommands after successful operations. Listen to a
specific event such as `AnsibleVaultEncrypt`, or to `AnsibleVaultOperation` for
all operations:

```lua
vim.api.nvim_create_autocmd("User", {
  pattern = "AnsibleVaultOperation",
  callback = function(event)
    vim.print(event.data.operation)
  end,
})
```

Current events are `AnsibleVaultEncrypt`, `AnsibleVaultDecrypt`,
`AnsibleVaultView`, `AnsibleVaultCreate`, `AnsibleVaultEditOpen`,
`AnsibleVaultEditSave`, `AnsibleVaultPlaintextSave`, `AnsibleVaultRekey`,
`AnsibleVaultStringEncrypt`, `AnsibleVaultStringDecrypt`, and
`AnsibleVaultDiff`.

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

The goal is that decrypted content never reaches the disk, including after
`kill -9` or a power loss. What the plugin guarantees:

- **No swap file.** `'swapfile'` is reset before plaintext enters a buffer, which
  also deletes any swap file that already existed for it.
- **No undo file.** `'undofile'` is off for decrypted buffers, and the undo
  history is cleared across every encrypt/decrypt transition.
- **No backup file.** Decrypted buffers use `'buftype'` `acwrite`, so Neovim
  skips its own write path entirely; `'backup'` and `'writebackup'` never apply.
- **No accidental plaintext write.** Every form of `:w` goes through the plugin
  and encrypts first. There is no way to write plaintext to disk by hand.
- **No password on disk.** Interactive passwords are passed to `ansible-vault`
  through the child process environment and read back by a static helper script
  in `stdpath("run")` that contains no secret. On platforms where that is not
  possible the plugin falls back to a `0600` temporary file, removes it on exit,
  and `:checkhealth` tells you which mode is in use.
- **Nothing secret in messages.** Process stdout is never echoed into an error,
  because `ansible-vault decrypt` can write plaintext to stdout and still exit
  non-zero. Debug logging redacts credential arguments and goes to `vim.notify`
  only, never to stdout.
- **No plaintext argv.** Content goes over stdin and passwords are passed by
  reference, so neither appears in `ps`.
- **Atomic writes.** Encrypted output is written to a sibling temporary file,
  `fsync`ed, then renamed into place, inheriting the original file's mode.

`make test-leak` enforces the first four: it kills Neovim while a file is
decrypted and searches Neovim's swap, undo and runtime directories for the
plaintext.

### What is still up to you

These are global Neovim settings the plugin deliberately does not change. Both
`:VaultInfo` and `:checkhealth ansible-vault` warn when they are enabled:

- **`'shada'`** persists registers, so text you *yank* out of a decrypted buffer
  or the `:VaultView` window is written to the shada file on exit. Consider
  `:set shada=` while working with secrets.
- **`'backup'`** applies to files written outside this plugin.
- **Decrypted content is in Neovim's memory** while you view or edit it, so it
  can reach the OS swap partition or a core dump. Review your other plugins,
  clipboard settings and terminal or session recording if that matters to you.
- **`:VaultDiff`** refuses to run when `'diffexpr'` is set or `'diffopt'` lacks
  `internal`, because Neovim would then write both sides to temporary files.

## Development

```sh
make test        # unit tests against a fake ansible-vault, no Ansible needed
make test-real   # end-to-end against a real ansible-core in .venv (needs uv)
make test-leak   # kills Neovim mid-decryption and greps for plaintext
make lint        # stylua --check and luacheck
make format      # stylua
```

`make test-real` and `make test-leak` create `.venv` and install `ansible-core`
on first run.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit message convention, which
release notes are generated from.

## License

MIT
