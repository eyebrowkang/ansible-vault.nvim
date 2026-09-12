# ansible-vault.nvim

Work with Ansible Vault files and inline `!vault` YAML values in Neovim, with
explicit save semantics and protection against unintended plaintext copies.

中文文档: [README.zh-CN.md](README.zh-CN.md)

## Features

- The capabilities of all seven `ansible-vault` subcommands through six editor
  commands: create, encrypt, decrypt, view, edit, rekey, and inline
  `encrypt_string` through a range on `:VaultEncrypt`.
- **Decrypt means plaintext.** Whole-file and inline `:VaultDecrypt` replace
  ciphertext in the current buffer; `:w` saves plaintext without re-encryption,
  another password prompt, or an extra confirmation.
- **Edit keeps the vault encrypted.** `:VaultEdit` uses a separate protected
  scratch buffer. Whole-file saves encrypt to the original file; inline saves
  encrypt one value back into the source buffer, leaving the source file for
  you to save.
- Read-only whole-file and inline views, encrypted file creation, and password
  rotation for both scopes.
- Inline YAML keys, indentation, list items and multiline scalar values are
  preserved through encryption, decryption, editing and rekeying.
- Upward `ansible.cfg` discovery from the current file, `ANSIBLE_*` settings,
  multiple password files or vault IDs, and per-command credential overrides.
- Protected plaintext buffers, no plaintext editor temporary files, no
  interactive password files, and a minimal `:checkhealth ansible-vault` report.

These are editor workflows, not wrappers that launch Ansible's `$EDITOR` or
create a plaintext temporary file for native `edit` or `create`. Viewing also
keeps plaintext in memory. See [Security](#security).

## Requirements

- The current Neovim release (currently 0.12).
- `ansible-vault` on `PATH`, or its path supplied to `setup()`.

### Version support policy

This plugin tracks the **current Neovim release only**. Older versions are not
worked around or tested; they may happen to work, but that is not a promise.
Keeping a single target keeps the maintenance effort manageable.
`:checkhealth ansible-vault` reports whether your version is supported.

### Stability policy before v1.0.0

**Before v1.0.0, this plugin provides no compatibility or migration guarantees.**
Commands, configuration and behaviour may change or be removed in any release.
There is no guaranteed deprecation period, compatibility alias, migration tool
or migration guide.

## Installation

### lazy.nvim

```lua
{
  "eyebrowkang/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup({
      password_files = "~/.ansible/vault-pass",
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

The six commands are available as soon as the plugin is loaded; calling
`setup()` is optional, and `require("ansible-vault").setup(opts)` is the only
function the module exports. For the full reference, see
`:help ansible-vault.nvim`.

## Commands

| Command | Whole file | Inline YAML value |
|---------|------------|-------------------|
| `:VaultCreate[!] {file}` | Protected empty buffer; `:w` encrypts to the target | — |
| `:VaultEncrypt` | Replace the entire buffer with ciphertext; you save it | Explicit `[range]` encrypts one YAML value; you save the source |
| `:VaultDecrypt` | Replace ciphertext with plaintext; `:w` saves plaintext | Replace one `!vault` block with a plaintext value; `:w` saves the source as shown |
| `:VaultView` | Read-only floating view | Read-only floating view of one value |
| `:VaultEdit` | Separate scratch; `:w` encrypts to the original file | Separate scratch; `:w` encrypts one block back into the source buffer only |
| `:VaultRekey` | Native rekey, publishing the new ciphertext to the file | Re-encrypt one block with new credentials; you save the source |

### How the target is chosen

- `:VaultCreate` always takes a filename.
- `:VaultEncrypt` **without a range always encrypts the whole buffer**, even
  after inline decryption. With an explicit range it encrypts one YAML value.
- For Decrypt, View, Edit and Rekey: an explicit range selects one inline block;
  otherwise a vault header on line 1 selects the whole file; otherwise the
  command finds the `!vault` block under the cursor.

An inline range must contain one complete value or block, not a truncated block,
multiple values, or neighbouring YAML entries. To encrypt the current line use
`:.VaultEncrypt`; for a multiline scalar, select its key and all its content.
Unparseable selections fail before changing the buffer.

Commands do not read stale `'<`/`'>` marks. A visual command such as
`:'<,'>VaultEncrypt` passes a range explicitly; a later normal-mode command does
not reuse that selection.

## Usage

### Encrypt or decrypt a whole file

To encrypt a plain file, run `:VaultEncrypt`, inspect the ciphertext, then `:w`.
Encryption changes the buffer, not the file on disk.

To write a vault as plaintext:

1. Open the encrypted file and run `:VaultDecrypt`.
2. Edit the plaintext if desired.
3. Run `:w` to save **plaintext** to the file.

There is no re-encryption, second password prompt, or extra confirmation on
that write. If the file changed on disk since it was decrypted, the save is
refused until you confirm with `:w!`.

From a buffer that has a file name, `:w another-file.yml` writes a plaintext
copy and leaves the buffer unsaved: the copy is not the buffer's own file. From
a buffer with no name there is nothing for the write to be "other" than, so
`:w some-file.yml` is that buffer being saved — it adopts the name and is
marked saved, the way an ordinary buffer would be.

The current buffer stays protected after a plaintext save. A normal plaintext
file opened in a later session is just a normal file: the plugin keeps no
history or metadata to identify it as a former vault.

Run `:VaultEncrypt` followed by `:w` if you want ciphertext on disk again. A
buffer that has been decrypted and re-encrypted in place keeps persistent undo
disabled for the rest of its life, so it has no cross-session undo; see
[Security](#security) for why, and why `:edit!` does not lift it. If you want
to edit while keeping the file encrypted throughout, use `:VaultEdit` instead.
`:edit!` discards buffer changes and reloads whatever is currently on disk;
after a plaintext save, that is plaintext.

### Create an encrypted file

```vim
:VaultCreate group_vars/prod/vault.yml
```

This opens an empty protected buffer. The target file is not created until
`:w`, and saves from this buffer write ciphertext only. Use `:VaultCreate!` to
allow replacing an existing file; it still does not overwrite it before the
first successful save. If the path is already open in another buffer, the
command reports that instead of emptying it.

### View without modifying the source

Run `:VaultView` on a whole vault or with the cursor inside an inline `!vault`
block. Plaintext opens in a protected, read-only floating window. Press `q` or
`<Esc>` to close and discard it. Viewing does not change the source buffer or
write plaintext to a temporary file.

The window refuses to write itself anywhere: `:w`, `:w {path}`, `:saveas` and
`:%w {path}` are all errors, the same as from an Edit or Create buffer. View is
a read-only verb, so if you want the decrypted content on disk, ask for it with
`:VaultDecrypt`.

### Edit while keeping the file encrypted

Run `:VaultEdit` on an unmodified, file-backed whole vault. The plugin opens the
plaintext in a separate protected scratch buffer. `:w` encrypts and atomically
writes to the original file; the scratch stays open so you can continue editing
and save again. Use `:q` or `:wq` when you are done.

The target is fixed: for both Edit and Create buffers, redirecting a write with
`:w other-file` is an error, not an export and not a request silently
redirected to the real target. Changes to the source buffer or file while an
edit is in progress cause the save to be refused rather than overwriting them.
Decrypting an inline value *inside* an Edit scratch adds plaintext to
plaintext; it does not turn the scratch into a buffer that saves itself in the
clear.

Opening Edit and each subsequent save are separate credential operations.
Interactive passwords are not cached, so opening and saving can each prompt.
`:wq` and `:x` wait for encryption and writing to finish; a failed save must not
close the scratch or discard its changes.

### Encrypt an inline YAML value

Pass the current line or a visual selection as a range:

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

The key is retained and only the value is encrypted. Select the complete scalar
for a multiline value:

```yaml
service:
  "private key": |-
    first line
    second line
```

Select `"private key"` and both content lines, not `service:` or its neighbours.
The inline workflow preserves quoted keys, nesting, list prefixes and value
content, including meaningful leading whitespace and trailing newlines. YAML
scalar presentation can change while preserving the value; decryption may use
a literal scalar to represent multiline content. A complete decrypted scalar
can be selected and encrypted again. Save the source YAML yourself with `:w`.

### Decrypt, edit or rekey one inline value

Place the cursor anywhere inside the `!vault` block, or explicitly select the
whole block:

```vim
:VaultView
:VaultDecrypt
:VaultEdit
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
```

**Decrypt** replaces that block with a plaintext YAML value in the source
buffer. Other values are unchanged. `:w` writes the YAML as shown, including the
decrypted value; it does not automatically turn values back into `!vault`
blocks. To encrypt just that value again, select its complete scalar and use
`[range]VaultEncrypt`. Without a range, `:VaultEncrypt` encrypts the entire YAML
buffer.

**Edit** opens just one value in a separate protected scratch. `:w` encrypts it
back into the source buffer, **without writing the source YAML file**. You must
return to the source buffer and save it yourself. Other unsaved YAML edits that
were already present when Edit opened are preserved.

After Edit opens, any change to the source buffer is conservatively treated as
a conflict, even outside the selected block. Source identity changes or removal
also prevent write-back. The plugin does not try to relocate the block through
intervening edits.

There is deliberately no `:w!` escape from that particular refusal. `:w!` does
override the *source file* check, because an inline write-back only touches the
buffer, so a changed file on disk cannot be damaged by it. The block snapshot
check is a different question — is the block still where it was? — and `!`
cannot supply the right position; forcing the write would overwrite whatever
value now sits there. The way out is to reopen `:VaultEdit` on the block: the
plaintext in the scratch is not lost, so you can carry it across.

After a successful write-back, you can continue editing and save the scratch
again against the updated snapshot.

**Rekey** decrypts the value in memory and encrypts it with the new credentials,
then replaces only that ciphertext block. Intermediate plaintext is never
inserted into the source buffer. Save the resulting YAML yourself.

Edit and Rekey need a YAML key to put the re-encrypted value back under, so a
`!vault` block that has none is refused. View and Decrypt still work on it.

### Rotate a whole file's password

Open an unmodified, file-backed whole vault and supply a new credential:

```vim
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
:VaultRekey --new-vault-id prod@~/.ansible/new-pass
```

The two new-credential flags are mutually exclusive. Old credentials come from
the normal sources or command overrides. Rekey runs Ansible's native `rekey`
on a restricted ciphertext staging file and atomically publishes the result
only if the original file is unchanged. The buffer then shows the new
ciphertext. A failure leaves the original vault intact.

A `1.2` header label is preserved when using a new password file; an explicit
`--new-vault-id` selects the new label. Native rekey does not use
`--encrypt-vault-id`: its label is supplied on the **new** identity so that
rotation actually uses the new password. Inherited encryption-identity defaults
are isolated for this child operation, without changing your configuration or
global environment.

## Configuration and credentials

`setup()` accepts these four settings:

```lua
require("ansible-vault").setup({
  ansible_vault_path = nil, -- executable path; nil uses PATH
  password_files = nil,    -- --vault-password-file: string or list
  vault_ids = nil,         -- --vault-id: string or list
  encrypt_vault_id = nil,  -- encryption identity label
})
```

Unknown keys and invalid values are errors and leave the current configuration
unchanged. To use a Conda or other environment, point `ansible_vault_path` at
`<env>/bin/ansible-vault`.

For multiple vault identities:

```lua
require("ansible-vault").setup({
  vault_ids = {
    "dev@~/.ansible/dev-pass",
    "prod@~/.ansible/prod-pass",
  },
  encrypt_vault_id = "prod",
})
```

`password_files` also accepts a string or list. If both credential settings are
present, `password_files` takes precedence. With no explicit encryption label,
Ansible chooses the identity; specify `encrypt_vault_id` to disambiguate multiple
identities. Edit preserves the existing `1.2` vault label unless you explicitly
choose another encryption identity. Decrypt writes plaintext, so its save has
no vault header to preserve.

### Credential precedence

1. Per-command credential overrides.
2. `setup()` credentials: `password_files`, then `vault_ids`.
3. `ANSIBLE_*` environment variables.
4. `ansible.cfg`.
5. An interactive password prompt when no credential source is available.

A command credential override replaces the configured credential selection,
not adds to it. Repeated flags build the list for that operation; they do not
retain unused entries from a configured list. Overrides do not mutate setup.
The plugin lets Ansible resolve environment/config-file credentials rather
than redundantly passing those credentials again as CLI flags.

### Command flags

| Flag | Use |
|------|-----|
| `--vault-password-file {path}` | Credential file; repeatable |
| `--vault-id {label@source}` | Vault identity; repeatable |
| `--ask-vault-password` | Prompt for this command, ignoring configured/discovered credentials |
| `--encrypt-vault-id {label}` | Encryption identity for Encrypt, Create or Edit |
| `--new-vault-password-file {path}` | Rekey's new password file |
| `--new-vault-id {label@source}` | Rekey's new identity |

Each flag is accepted only by the commands it can mean something for, so a flag
that would be a silent no-op is an error instead. `:VaultRekey` in particular
does not accept `--encrypt-vault-id`: on Ansible's `rekey` that flag chooses
from a pool seeded with the **old** identities, so accepting it would let a
rotation report success with the file still on its old password.

Prompting and new rekey credentials are command flags, not persistent setup
options. Do not combine competing credential selectors, or both new-credential
flags. Unknown flags, missing values, flags inappropriate for the command and
stray arguments are errors; Create takes one filename.

Paths may be quoted or backslash-escaped:

```vim
:VaultView --vault-password-file '/path with spaces/pass'
:VaultEdit --vault-password-file /path\ with\ spaces/pass
:VaultEncrypt --vault-id dev@~/.dev-pass --vault-id prod@~/.prod-pass --encrypt-vault-id prod
:VaultDecrypt --ask-vault-password
:VaultCreate 'group_vars/prod/private vault.yml'
```

Completion offers the command's supported flags and filenames for Create.

### ansible.cfg discovery

Upward discovery is a core editor adaptation: Ansible checks the process
working directory, but that need not be the directory of the file you are
editing. The plugin searches in this order:

1. `$ANSIBLE_CONFIG` (a file, or a directory containing `ansible.cfg`).
2. `ansible.cfg` or `.ansible.cfg`, walking upward from the current file.
3. `~/.ansible.cfg`.
4. `/etc/ansible/ansible.cfg`.

The child process runs in the discovered config directory, and relative paths
in that config resolve as Ansible expects, relative to the config file itself.
The relevant `[defaults]` settings are `vault_password_file`,
`vault_identity_list`, `vault_identity`, `vault_encrypt_identity` and
`ask_vault_pass`; matching environment variables take precedence.

### Health check

```vim
:checkhealth ansible-vault
```

The report covers Neovim support, executable availability, configuration and
credential sources, and necessary privacy warnings. It does not prompt for a
password or create the interactive-password helper just to run diagnostics.

## Keymaps

No keymaps are installed by default. For example:

```lua
vim.keymap.set("n", "<leader>vc", ":VaultCreate ", { desc = "Vault Create" })
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", ":VaultRekey ", { desc = "Vault Rekey" })

-- Use `:` in visual mode to pass the selection as an explicit range.
vim.keymap.set("x", "<leader>ve", ":VaultEncrypt<cr>", { silent = true })
vim.keymap.set("x", "<leader>vd", ":VaultDecrypt<cr>", { silent = true })
vim.keymap.set("x", "<leader>vv", ":VaultView<cr>", { silent = true })
vim.keymap.set("x", "<leader>vE", ":VaultEdit<cr>", { silent = true })
```

Create and Rekey mappings leave the command line open for the filename or new
credential. Normal-mode Decrypt, View, Edit and Rekey use the target rules above;
`<cmd>` visual mappings would not pass a range.

## Security

The privacy goal is to avoid **unintended copies**, not to prohibit an explicit
plaintext save. `:VaultDecrypt` followed by `:w` intentionally writes plaintext.
View has no plaintext save path, and temporary Edit/Create buffers save only
ciphertext through their controlled writers.

- **Harden before insertion.** Managed plaintext buffers have `'swapfile'` and
  `'undofile'` disabled before plaintext arrives. Clearing `'swapfile'` removes
  that buffer's existing swap file. The guarantee across plaintext/ciphertext
  transitions is that plaintext does not reach the undo *file* — sometimes by
  clearing the undo history, sometimes by leaving `'undofile'` off for good.
  After `[range]VaultEncrypt`, for instance, `:undo` can still bring the value
  you just encrypted back **in memory**; that buffer's `'undofile'` is off
  permanently, so it cannot be written out.
- **Controlled writes, no Neovim backup copies.** Writable managed buffers use
  `'buftype'` `acwrite`, bypassing Neovim's ordinary write/backup path. Decrypt's
  writer saves plaintext by design; Edit/Create writers encrypt. Saving a
  decrypted buffer as plaintext does not remove its current buffer protection.
  Encrypting a single range does not prove the rest of the buffer is free of
  plaintext; only a successful whole-buffer encryption restores ordinary write
  behaviour, and even then not `'undofile'` (see the next point).
- **No partial or appending writes.** `acwrite` covers `:w`, `:w {file}` and
  `:saveas`, but not a partial-range write or an append. With no handler for
  those, Neovim writes the lines out itself: unencrypted, not atomically, and
  with the umask's permissions rather than `0600`. So `:1w {file}` and
  `:w >> {file}` are refused outright, on managed buffers and on the View
  window. A **whole-buffer** `:w {path}` from a decrypted buffer is a save you
  asked for and still goes through the atomic writer, which creates a new file
  `0600` but leaves an existing target's mode alone.

  This interception is not total, and the gap is worth naming since the rest of
  this list enumerates what *is* covered: piping the buffer through a shell —
  `:w !cat > f`, `:1,2w !cat > f`, `:%!tee f` — raises no event the plugin can
  hook, so those write the plaintext out at the shell's discretion, typically
  `0644`. That is treated as your explicit instruction rather than a leak, in
  the same category as yanking out of a decrypted buffer with `'shada'` on.
- **Persistent undo comes back only when it is provably safe.**
  Turning `'undofile'` off while the plaintext is in the buffer is not enough on
  its own: on the next ordinary write Neovim serializes the text a change
  *replaced*, so a buffer that was decrypted and then re-encrypted in place
  would write the plaintext it had just encrypted away into the persistent undo
  file — while the file on disk never held anything but ciphertext. Restoring
  `'undofile'` is therefore safe only once the undo history itself is gone, and
  that, not anything else, is what gates it: the plugin discards the history and
  only then hands persistent undo back. A read replacing the buffer's contents
  does **not** make it safe by itself, because the reload is one more undoable
  change still holding the plaintext it replaced.

  The net effect has two halves. A buffer reloaded while the plugin was still
  managing it gets cross-session undo back, because its history is cleared
  first. A buffer that was decrypted and re-encrypted **in place** keeps
  `'undofile'` off for the rest of its life and has no cross-session undo;
  `:edit!` does not bring it back, because that restore only runs for a reload
  that still had a live session. These are buffer-local options, so a buffer
  opened fresh for the same file later is unaffected. Undo *within* a session is
  never affected either way.
- **Protection outlasts a failed reload.** Reloading a managed buffer drops the
  plugin's write handler immediately, but restores the hardened options only
  once a read has actually replaced the plaintext. If that read fails, the
  buffer keeps `'buftype'` `acwrite` with no handler behind it, so `:w` fails
  with `E676` rather than falling back to Neovim's own write path. Nothing is
  lost: the buffer is already empty at that point, because Neovim frees its
  contents before reading. Use `:bd`, or edit the file again successfully —
  including re-editing a file that has since been deleted — and the buffer
  returns to normal.
- **No historical tracking.** A deliberately saved plaintext file reopened
  later is an ordinary file. There is no database, sidecar or metadata recording
  its former vault status, and no promise to protect unrelated future buffers.
- **No plaintext editor temporary files.** View/Edit do not hand secrets to an
  external editor. Ciphertext operations stage ciphertext only. An explicit
  Decrypt save uses an atomic plaintext replacement, so its intended output,
  including that replacement's temporary staging file, can contain plaintext.
- **No interactive password files or cache.** A static, non-secret helper reads
  the password from the child process environment. The password is not put in
  argv, log messages or a file. If the safe helper is unavailable, prompting
  fails explicitly; user-supplied credential files remain usable. Interactive
  passwords are not retained for reuse between operations, including Edit saves.
- **Safe error summaries.** CLI errors do not include raw stdout/stderr,
  environment or complete command arguments, which may contain secrets.
- **Guarded writes.** Operations check for intervening buffer/file changes.
  Atomic replacement preserves existing file permissions; failed encryption or
  conflicting saves must not overwrite the source or discard unsaved edits.

### What is still up to you

The plugin does not change global `'shada'`, `'backup'` or `'writebackup'`
settings; the health check warns about relevant persistence risks instead.
Registers you yank into may be saved in ShaDa, copied to the clipboard or used
by another plugin. Backups still apply to writes outside the plugin's managed
buffers. Review these settings and other plugins when handling secrets.

Explicit plaintext writes, manual exports, registers, other plugins, external
processes and terminal/session recording are outside this protection. Plaintext
and passwords necessarily exist in process memory while used; the plugin does
not promise memory erasure or protection against OS swap, core dumps or another
process with access to that memory or the child environment.

The crash-leak checks distinguish a requested plaintext output from unexpected
swap, undo, backup and runtime copies. They are not a guarantee against every
form of system-level persistence.

## Development

```sh
make test        # command-driven tests with a fake ansible-vault
make test-real   # end-to-end with real ansible-core in .venv (needs uv)
make test-leak   # crash checks for unintended plaintext copies
make lint        # stylua --check and luacheck
make format      # stylua
```

`make test-real` and `make test-leak` create `.venv` and install `ansible-core`
on first run. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and commit
message convention used to generate release notes.

## License

MIT
