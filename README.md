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

**Credentials**

- Reads `ansible.cfg` and the `ANSIBLE_*` environment variables the way Ansible
  does, searching upward from the current file
- One or more password files or vault IDs, or an interactive prompt
- Per-command credential overrides with command-line completion

**Fidelity**

- Preserves the vault ID label in a `1.2` header instead of silently rewriting
  the file as `1.1`
- Handles every inline shape Ansible accepts: `|`, `|-`, `>`, `|2`, quoted keys,
  list items and arbitrary nesting

**Integration**

- `:checkhealth ansible-vault`
- A `User` autocmd event for statuslines and other plugins

## Requirements

- Neovim >= 0.12
- `ansible-vault` command available in PATH, or its path given to `setup()`

### Version support policy

This plugin tracks the **current Neovim release only**. Older versions are not
worked around and are not tested; they may happen to work, but that is not a
promise. Keeping a single target is what keeps the plugin maintainable with the
effort available. `:checkhealth ansible-vault` tells you whether your version is
supported.

## Installation

### lazy.nvim

```lua
{
  "eyebrowkang/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup({
      -- Optional: --vault-password-file (a string or a list)
      password_files = "~/.vault_pass",
      -- Optional: --vault-id (a string or a list)
      vault_ids = nil,
      -- Optional: --encrypt-vault-id
      encrypt_vault_id = nil,
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
  -- --vault-id. A single string, or a list for multi-vault setups.
  vault_ids = nil,

  -- --vault-password-file. A single string, or a list.
  password_files = nil,

  -- Always prompt, ignoring any configured or discovered credential.
  -- Cannot be combined with vault_ids or password_files.
  ask_password = false,

  -- --encrypt-vault-id: which identity to encrypt with.
  -- Leave nil to let ansible-vault choose from the configured vault IDs.
  encrypt_vault_id = nil,

  -- --new-vault-id for :VaultRekey, for example "prod@~/.ansible/new-pass"
  new_vault_id = nil,

  -- --new-vault-password-file for :VaultRekey.
  -- Mutually exclusive with new_vault_id, as in ansible-vault itself.
  new_password_file = nil,

  -- Custom path to ansible-vault executable
  ansible_vault_path = nil,
})
```

### Password Sources

The plugin resolves credentials in this order:

1. per-command overrides, such as `:VaultEncrypt --vault-id prod@~/.prod-pass`
2. `setup()` configuration: `ask_password`, then `password_files`, then
   `vault_ids`
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
`vault_encrypt_identity` and `ask_vault_pass`.

Run `:checkhealth ansible-vault` to see which config was found and which
credential source is actually in effect.

Use `password_files` for a single vault password:

```lua
require("ansible-vault").setup({
  password_files = "~/.ansible/vault-pass",
})
```

Use `vault_ids` for Ansible multi-vault setups. Both keys take a single string
or a list, because the flags they stand for are repeatable:

```lua
require("ansible-vault").setup({
  vault_ids = {
    "dev@~/.ansible/dev-pass",
    "prod@~/.ansible/prod-pass",
  },
  encrypt_vault_id = "prod",
})
```

Set `ask_password = true` to always prompt, for a vault whose password is not
written down anywhere:

```lua
require("ansible-vault").setup({
  ask_password = true,
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
:VaultEncryptString --encrypt-vault-id prod
:VaultDecrypt --ask-vault-password
```

Flags are spelled exactly as `ansible-vault` spells them, and an unrecognised
one is an error rather than being silently ignored — a typo used to fall through
to a password prompt, which reads as "the credential was not found".

Configure `VaultRekey` with a new password file or a new vault ID:

```lua
require("ansible-vault").setup({
  password_files = "~/.ansible/old-pass",
  new_password_file = "~/.ansible/new-pass",
})
```

```lua
require("ansible-vault").setup({
  vault_ids = "old@~/.ansible/old-pass",
  new_vault_id = "new@~/.ansible/new-pass",
})
```

If `ansible-vault` is not on `PATH`, point to the executable directly:

```lua
require("ansible-vault").setup({
  ansible_vault_path = "/opt/homebrew/bin/ansible-vault",
  password_files = "~/.ansible/vault-pass",
})
```

The same option covers a Conda environment — point it at
`<env>/bin/ansible-vault`.

Interactive passwords are never cached. Each operation prompts for its own, so
no secret sits in Neovim's memory between operations.

## Commands

| Command | Description |
|---------|-------------|
| `:VaultEncrypt` | Encrypt current buffer |
| `:VaultDecrypt` | Decrypt current buffer for editing; `:w` re-encrypts |
| `:VaultCreate {file}` | Create a new encrypted file (`!` overwrites) |
| `:VaultView` | View decrypted content in floating window |
| `:VaultEdit` | Edit encrypted file in a scratch buffer, encrypt on save |
| `:VaultRekey [args]` | Rekey the current encrypted file |
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
  password_files = "~/.ansible/old-pass",
  new_password_file = "~/.ansible/new-pass",
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

A `1.2` vault ID label survives the rekey: the plugin names it on the new
identity, as `--new-vault-id prod@<new-password-file>`. It never passes
`--encrypt-vault-id` to `rekey`, because on that subcommand the flag selects the
*new* secret from a pool seeded with the *old* identities from `ansible.cfg` —
which either fails outright or re-encrypts the file with the old password and
still reports success.

## Keymaps

The plugin doesn't set any keymaps by default. You can add your own:

```lua
vim.keymap.set("n", "<leader>vc", "<cmd>VaultCreate<cr>", { desc = "Vault Create" })
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", "<cmd>VaultRekey<cr>", { desc = "Vault Rekey" })
vim.keymap.set("v", "<leader>vs", ":VaultEncryptString<cr>", { silent = true, desc = "Vault Encrypt String" })
vim.keymap.set("v", "<leader>vS", ":VaultDecryptString<cr>", { silent = true, desc = "Vault Decrypt String" })
vim.keymap.set("v", "<leader>vv", ":VaultViewString<cr>", { silent = true, desc = "Vault View String" })
vim.keymap.set("n", "<leader>vs", "<cmd>VaultEncryptStringUnderCursor<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("n", "<leader>vS", "<cmd>VaultDecryptStringUnderCursor<cr>", { desc = "Vault Decrypt String" })
```

## Statusline Integration

Use `is_buffer_encrypted()`, which inspects the buffer every time rather than
relying on state left behind by an earlier operation:

```lua
-- For lualine
require("lualine").setup({
  sections = {
    lualine_x = {
      {
        function()
          return require("ansible-vault").is_buffer_encrypted() and "[VAULT]" or ""
        end,
      },
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

-- Drop every secret this process still holds (also runs on VimLeavePre)
vault.cleanup()
```

## User Events

The plugin emits one `User` autocommand pattern, `AnsibleVaultOperation`, after
every successful operation:

```lua
vim.api.nvim_create_autocmd("User", {
  pattern = "AnsibleVaultOperation",
  callback = function(event)
    vim.print(event.data.op, event.data.scope)
  end,
})
```

The event `data` carries `op` (`"encrypt"`, `"decrypt"`, `"view"`, `"edit"`,
`"save"`, `"rekey"` or `"create"`), `scope` (`"file"` or `"inline"`) and the
buffer and file it applied to. One pattern means one autocmd can react to
everything and filter on `op`/`scope`.

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
  non-zero. Any argv the plugin does surface has its credential values
  redacted.
- **No plaintext argv.** Content goes over stdin and passwords are passed by
  reference, so neither appears in `ps`.
- **Atomic writes.** Encrypted output is written to a sibling temporary file,
  `fsync`ed, then renamed into place, inheriting the original file's mode.

`make test-leak` enforces the first four: it kills Neovim while a file is
decrypted and searches Neovim's swap, undo and runtime directories for the
plaintext.

### What is still up to you

These are global Neovim settings the plugin deliberately does not change.
`:checkhealth ansible-vault` warns when they are enabled:

- **`'shada'`** persists registers, so text you *yank* out of a decrypted buffer
  or the `:VaultView` window is written to the shada file on exit. Consider
  `:set shada=` while working with secrets.
- **`'backup'`** applies to files written outside this plugin.
- **Decrypted content is in Neovim's memory** while you view or edit it, so it
  can reach the OS swap partition or a core dump. Review your other plugins,
  clipboard settings and terminal or session recording if that matters to you.

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
