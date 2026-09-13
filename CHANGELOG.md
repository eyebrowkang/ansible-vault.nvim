# Changelog

All notable changes to this project are documented here.
[git-cliff](https://git-cliff.org) seeds a draft from commit history; maintainers
then curate and commit each release entry before its tag is created.

## [0.2.0](https://github.com/eyebrowkang/ansible-vault.nvim/releases/tag/v0.2.0) - 2026-09-13

This release reduces the plugin to six scope-aware commands and four settings.
Before v1.0.0 there are no compatibility or migration guarantees; removed
`setup()` keys and command arguments now error rather than silently doing
nothing, so leftover configuration reports itself.

### Breaking Changes

- **BREAKING** `:VaultDecrypt` now decrypts: the buffer holds plaintext and `:w`
  saves that plaintext, with no re-encryption, second password prompt, or extra
  confirmation. Use `:VaultEncrypt` then `:w` to put ciphertext back on disk.
- **BREAKING** `:VaultEncrypt` without a range always encrypts the whole buffer.
  Use `[range]VaultEncrypt` (for example, `:.VaultEncrypt`) for one inline value;
  no command reads the `'<`/`'>` marks any more, and charwise and blockwise
  selections are no longer supported.
- **BREAKING** Seventeen commands become six. `:VaultEncryptString`,
  `:VaultDecryptString`, `:VaultViewString`, the three
  `:Vault*StringUnderCursor` twins, `:VaultDiff`, `:VaultFiles`, `:VaultInfo`,
  `:VaultToggle`, and `:VaultClearPasswordCache` are removed. `:VaultEncrypt`,
  `:VaultDecrypt`, `:VaultView`, `:VaultEdit`, `:VaultRekey`, and `:VaultCreate`
  each pick their target from an explicit `[range]`, a vault header on line 1, or
  the `!vault` block under the cursor. `:VaultRekey` now works on inline values
  too.
- **BREAKING** `require("ansible-vault")` exports `setup()` and nothing else.
  The operation API, inline-string helpers, `status()`, `is_buffer_encrypted()`,
  `parse_header()`, `cleanup()`, and `vim.g.ansible_vault_config` are removed.
- **BREAKING** All `User` autocmd events are removed, including
  `AnsibleVaultOperation` and the per-operation `AnsibleVault*` patterns, along
  with the `vim.b.ansible_vault_encrypted` marker. There is no statusline
  integration.
- **BREAKING** `setup()` now takes four keys: `password_files`, `vault_ids`,
  `encrypt_vault_id`, and `ansible_vault_path`. `password_file` and `vault_id`
  become plural, repeatable forms. `rekey_password_file`, `rekey_vault_id`,
  `auto_detect`, `auto_edit`, `password_cache_ttl`, `picker`, `timeout_ms`,
  `notify_success`, `conda_env`, and `debug` are gone. Unknown keys and wrong
  value types are errors that leave the configuration unchanged.
- **BREAKING** Prompting and rekey targets are command arguments, not settings:
  `--ask-vault-password`, `--new-vault-password-file`, and `--new-vault-id`.
  `--vault-pass-file`, `--password-file`, and the bare-label shortcut are
  removed; unknown flags, missing values, and stray arguments are errors.
- **BREAKING** `:VaultRekey` no longer accepts `--encrypt-vault-id`; use
  `--new-vault-id label@source` to set the new label. **Verify any labelled file
  you rekeyed under v0.1.0 — it may still open with the old password.**
- **BREAKING** Interactive passwords are never cached, and there is no fallback
  to a temporary password file: if the askpass helper cannot be installed, the
  operation fails instead of writing a `0600` file.
- **BREAKING** Opening an encrypted file does nothing until you ask; the plugin
  registers no `BufReadPost` autocmd. Conda users point `ansible_vault_path` at
  `<env>/bin/ansible-vault`.

### Features

- `:VaultRekey` on a single inline `!vault` value decrypts with the old
  credentials and re-encrypts with the new ones, leaving the block untouched on
  failure and never putting intermediate plaintext in the buffer.
- `--ask-vault-password` requests an interactive password for one operation, and
  `ask_vault_pass` from your Ansible configuration is honoured instead of parsed
  and ignored.
- Keyless `!vault` blocks, including list items, support View, Decrypt, Edit,
  and Rekey — not just the Create path that produces them.

### Bug Fixes

- Rekeying a labelled vault could report success and leave the file on its old
  password, or fail outright as un-rekeyable. The label is now carried on the
  new identity, and the child process no longer inherits an encryption identity
  that seeds the new secret pool from the old one.
- Encryption could use a password you did not name: an identity from
  `ansible.cfg` outranked a `--vault-id` given on the command line. The plugin's
  identities now come first for the child process only.
- A labelled 1.2 file could not be saved with only `password_files` configured,
  and more than one password file made encryption fail with "The vault-ids
  default,default are available to encrypt". Both work now.
- Vault identities whose source is `prompt` or `prompt_ask_vault_pass`, including
  ones inherited from your Ansible configuration, are asked for inside Neovim —
  once per operation, separately per identity — instead of letting Ansible read
  a password from the content on stdin.
- The discovered Ansible configuration is now passed to `ansible-vault` as
  `ANSIBLE_CONFIG`, so project `.ansible.cfg` files and relative paths take
  effect instead of being silently ignored.
- `:VaultEdit` no longer stores resolved credentials, including an interactive
  password's environment, in the `b:vault_creds` buffer variable.
- Plaintext could reach a persistent undo file after decrypting and re-encrypting
  a buffer in place; `'undofile'` now stays off until the contents have been
  replaced by a read.
- Partial writes (`:1w file`) and append writes (`:w >> file`) wrote unencrypted
  content from protected buffers, and `:w {path}` from the `:VaultView` float put
  decrypted content on disk. All are refused.
- `:saveas` on a decrypted buffer left it permanently unsaveable, and the
  decrypted round trip now derives `'fileformat'` and `'endofline'` from the
  content instead of the vault file, keeping it byte-exact.
- Inline encryption no longer swallows a trailing `#` comment into a plain scalar
  that contains a quote, and multiline values in keyless YAML lists keep their
  original indentation.

### Documentation

- README, the Chinese README, and the vimdoc are rewritten for people using the
  plugin: what each command does, what each `:w` produces, how to supply a
  password, and what to do when an operation is refused.

## [0.1.0](https://github.com/eyebrowkang/ansible-vault.nvim/releases/tag/v0.1.0) - 2026-09-10

### Features

- Harden vault workflows and docs
- Add vault health and inline workflows
- Add vault navigation and convenience workflows
- Add vault diagnostics and real smoke tests

### Bug Fixes

- B1-B11 bug fixes, plugin commands, CI, vimdoc, LICENSE ([#1](https://github.com/eyebrowkang/ansible-vault.nvim/pull/1))
- Protect unnamed decrypted buffers from being written out as plaintext
- Preserve line endings when writing a partially decrypted file
- Install the askpass helper atomically
- Remove only our own BufWriteCmd when leaving plaintext mode
- Read 'diffopt' from the option string, not the structured view

### Refactor

- Split credentials, secure, yaml and ansible.cfg modules
- **BREAKING** Track the current Neovim release only

### Documentation

- Rewrite README around the privacy model and new credential resolution
- Update vimdoc and Chinese README for the new privacy model

### Testing

- Cover privacy guarantees, inline shapes and ansible.cfg discovery
- Add a crash-leak harness that kills Neovim mid-decryption

### Build & CI

- Generate releases from the commit history with git-cliff
