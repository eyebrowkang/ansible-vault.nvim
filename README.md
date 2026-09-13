# ansible-vault.nvim

Encrypt, decrypt, view, edit and rekey Ansible Vault files and inline YAML
`!vault` values in Neovim. Create new encrypted files without leaving the editor.

中文文档: [README.zh-CN.md](README.zh-CN.md)

## Installation

- **Neovim 0.12**. Other versions are not guaranteed to work.
- **Ansible**, with `ansible-vault` on `PATH`. See the
  [official installation guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html).
  If needed, set `ansible_vault_path` below.

With [lazy.nvim](https://github.com/folke/lazy.nvim):

```lua
{ "eyebrowkang/ansible-vault.nvim" }
```

With packer.nvim:

```lua
use { "eyebrowkang/ansible-vault.nvim" }
```

`setup()` is optional. All six commands are available once the plugin is loaded;
you do not need a password file to get started.

Before v1.0.0, commands, configuration and behaviour may change without
compatibility or migration guarantees.

## Quick start

Open an encrypted file and run:

```vim
:VaultEdit
```

With no credentials configured, enter the vault password when prompted. Edit in
the separate buffer, then `:w` to encrypt and save to the original file. A
successful write ends the protected editing session and returns to the refreshed
ciphertext buffer; run `:VaultEdit` again for another plaintext edit. Enter the
password again if prompted; passwords are not cached. `:wq` and `:x` wait for
the real save result and close only after success.

**Want plaintext on disk instead?** Use `:VaultDecrypt`, then `:w`.
That write saves **plaintext**, without re-encryption, another password prompt
or an extra confirmation.

## Commands and saving

| Command | Whole file | Inline YAML value |
|---------|------------|-------------------|
| `:VaultCreate[!] {file}` | Open an empty protected buffer; a successful `:w` encrypts to the chosen file, disposes it, and shows ciphertext | Not applicable |
| `:VaultEncrypt` | Encrypt the entire buffer; then `:w` to save | With `[range]`, encrypt one value; then save the source YAML |
| `:VaultDecrypt` | Replace ciphertext with plaintext; `:w` saves plaintext | Replace one `!vault` block with plaintext; `:w` saves the YAML as shown |
| `:VaultView` | Read-only floating view; writing is refused | Read-only view of one value; writing is refused |
| `:VaultEdit` | Separate protected buffer; a successful `:w` encrypts to the original file, disposes it, and returns to refreshed ciphertext | Separate protected buffer; a successful `:w` encrypts back into the source buffer **only**, disposes it, and returns there |
| `:VaultRekey` | Change credentials and save new ciphertext to the file | Change credentials for one block; then save the source YAML |

Create and Edit buffers are **unlisted**: they are named `ansible-vault://…` and
would otherwise show up beside the file they came from under the same name. They
live in their window until the save that ends the session. If you navigate a
window away from one with unsaved changes, `<C-^>` goes back to it, and `:ls!`
lists it.

Create and whole-file Edit save to a **fixed target**. They do not allow
`:w other-file` or `:saveas` to choose a different file. Inline Edit opens the
value in a split and never saves the source file: its successful protected save
closes that split and returns to the source buffer, where you run a separate
normal `:w` yourself. View refuses all writes; press `q` or `<Esc>` to close it.

A successful Create or Edit save ends its protected editing session. Failed
saves keep the protected buffer open and retain your changes for retry.
Whole-file Edit and Rekey require an encrypted file with no unsaved buffer
changes; `:wq` and `:x` wait for the save to finish.

### Choosing the target

- Create takes one filename and works only on files.
- **Without a range, Encrypt always encrypts the entire buffer**, even after
  decrypting an inline value.
- For Decrypt, View, Edit and Rekey: an explicit range selects one inline block.
  Otherwise, a vault header on line 1 selects the whole file; if there is no
  header there, the command uses the `!vault` block under the cursor.
- A previous visual selection is not reused by a later normal-mode command.

To encrypt a plain file, run `:VaultEncrypt`, then `:w`. To create a new vault:

```vim
:VaultCreate group_vars/prod/vault.yml
```

The file is not created until the first successful `:w`, which closes the Create
scratch and opens the new ciphertext file. `:VaultCreate!` allows replacing an
existing file, but not a path already open in another buffer.

### Inline YAML

Encrypt the current line or a visual selection:

```vim
:.VaultEncrypt
:'<,'>VaultEncrypt
```

For example, `password: secret` becomes:

```yaml
password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  3132333435...
```

Select exactly one complete scalar. For a multiline value, include its key and
all content lines, but not its parent or neighbouring entries:

```yaml
service:
  "private key": |-
    first line
    second line
```

Here, select `"private key"` and the two lines below it. Quoted keys, indentation,
list items and value content are preserved, including meaningful whitespace and
newlines. Scalar formatting may change while keeping the same value.

To View, Decrypt, Edit or Rekey a value, put the cursor anywhere inside its
`!vault` block, or select the complete block. Keyless blocks, including list
items, also support all four commands.

After inline Decrypt, `:w` saves the plaintext value alongside any still-encrypted
values. To encrypt just that value again, select its complete scalar and use
`[range]VaultEncrypt` — not a range-less `:VaultEncrypt`.

Inline Edit preserves unsaved YAML changes that existed when it opened. Avoid
changing the source buffer while editing the value: later source changes block
write-back, even outside that block, and `:w!` cannot override this conflict.
See `:help ansible-vault-troubleshooting` for recovery steps.

### Rotate a password

Supply one new credential; the old credential comes from the usual sources:

```vim
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
:VaultRekey --new-vault-id prod@~/.ansible/new-pass
```

These two new-credential flags are mutually exclusive. A new password file keeps
the existing vault label by default; `--new-vault-id` can choose a new label. Rekey does not
accept `--encrypt-vault-id`. Whole-file Rekey saves the file immediately; inline
Rekey changes only the source buffer and leaves you to save it.

## Passwords and configuration

Choose whichever of these three paths fits your setup.

### 1. Enter a password when prompted

No `setup()` or password file is needed. With no credential source available,
the plugin prompts for a password. To request a prompt for a particular command:

```vim
:VaultDecrypt --ask-vault-password
```

Passwords are obtained separately for each operation and are not cached. Opening
an Edit session and each attempted Edit/Create write can prompt separately; a
successful Create/Edit write ends that session. Saving after Decrypt does not
need a password.

### 2. Use existing password files or vault IDs

```lua
require("ansible-vault").setup({
  password_files = "~/.ansible/vault-pass",
})
```

Or, for multiple identities:

```lua
require("ansible-vault").setup({
  vault_ids = { "dev@~/.ansible/dev-pass", "prod@~/.ansible/prod-pass" },
  encrypt_vault_id = "prod",
})
```

Both `password_files` and `vault_ids` accept a string or a list. If both are set,
`password_files` takes precedence. Executable password scripts are supported. A
vault ID whose source is `prompt` or `prompt_ask_vault_pass`, including one
inherited from your Ansible configuration, is asked for in Neovim: once per
operation, separately per identity, never cached.

These are the four available settings, all optional:

| Setting | Value | Default |
|---------|-------|---------|
| `ansible_vault_path` | Executable path, e.g. `<env>/bin/ansible-vault` | `nil`: use `PATH` |
| `password_files` | Password file or list of files | `nil` |
| `vault_ids` | `label@source` or a list of identities | `nil` |
| `encrypt_vault_id` | Identity label to encrypt with | `nil`: reuse an applicable existing label, otherwise let Ansible choose |

Choose `encrypt_vault_id` when multiple labels are available. Unknown settings
and wrong value types are errors and leave the current configuration unchanged.

### 3. Use your existing Ansible configuration

You can leave `setup()` out and use `ANSIBLE_*` variables or `ansible.cfg`.
Configuration discovery checks:

1. `$ANSIBLE_CONFIG`: a file, or a directory containing `ansible.cfg` or `.ansible.cfg`.
2. `ansible.cfg` or `.ansible.cfg`, searching upward from the current file
   (the working directory if there is no usable file directory).
3. `~/.ansible.cfg`.
4. `/etc/ansible/ansible.cfg`.

Paths in the config file resolve relative to that file. Environment variables
override the corresponding Ansible settings.

Normal credential priority is **command arguments → `setup()` password files →
`setup()` vault IDs → Ansible environment/configuration → interactive prompt**.
Command credentials replace the plugin's configured selection for that operation;
they do not change `setup()`.

**Prompting exception:** `--ask-vault-password` requests interactive input.
An effective `ask_vault_pass = true` / `ANSIBLE_ASK_VAULT_PASS=true` also takes
priority over password files and vault IDs, even those supplied on the command
line. Disable that setting if you want to use a file instead.

For the six supported argument types, quoting, label selection and full
precedence details, see `:help ansible-vault-command-args` and
`:help ansible-vault-passwords`.

## Keymaps

No keymaps are set by default. For example:

```lua
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
-- Use `:` in visual mode to pass the selection as a range.
vim.keymap.set("x", "<leader>ve", ":VaultEncrypt<cr>", { silent = true })
```

More examples: `:help ansible-vault-keymaps`.

## Protection and limits

The plugin protects against **unintended plaintext copies**, not a plaintext
save you request with Decrypt.

- Managed plaintext buffers disable swap files and persistent undo, and their
  saves do not create Neovim backup copies. View/Edit/Create do not create
  plaintext editing files. Interactive passwords are not written to files.
- Protection remains on the current buffer after a plaintext save. A saved
  plaintext file reopened later is an ordinary file, not a protected vault.
- In-place encryption can leave persistent undo disabled for the buffer's
  remaining lifetime, including after `:edit!`. This means no cross-session undo;
  ordinary in-memory undo remains available after range encryption. Reloads may
  clear undo history. See `:help ansible-vault-security`.
- Partial writes such as `:1w file` and append writes such as `:w >> file` are
  refused in protected buffers. For a named decrypted buffer, bare `:w` keeps its
  target across `:cd`; use `:w ./copy.yml` for an intentional plaintext copy in
  the current directory, or `:saveas ./name` to adopt a new target. Edit/Create
  have fixed targets and View refuses writing entirely.
- A save after Decrypt fires `BufWritePre`/`BufWritePost`, so your statusline and
  save hooks see it like any other write. A Create or Edit save does not: it
  writes ciphertext to a different path, and those events would hand the
  decrypted buffer to every formatter and linter listening for them.
- Registers, ShaDa, the clipboard, other plugins, shell commands and terminal
  recording are outside this protection. Global `'shada'`, `'backup'` and
  `'writebackup'` settings are not changed. Neither process memory nor OS swap,
  core dumps or other system-level copies are protected.

## Troubleshooting

Run `:checkhealth ansible-vault` to check Neovim, the executable, credential
sources and relevant privacy warnings. It does not ask for a password.

- Command missing? Check that your plugin manager has loaded the plugin.
- Executable missing? Install Ansible or set `ansible_vault_path`.
- Wrong password source? Check the health report, `ANSIBLE_CONFIG` and the
  prompting exception above.
- Save refused? Keep the editing buffer open and check for source changes or a
  redirected/partial write. Do not discard edits just to retry.

Full reference and recovery steps: `:help ansible-vault.nvim` and
`:help ansible-vault-troubleshooting`.

## License

MIT
