# Changelog

All notable changes to this project are documented here.
[git-cliff](https://git-cliff.org) seeds a draft from commit history; maintainers
then curate and commit each release entry before its tag is created.

## [0.3.0](https://github.com/eyebrowkang/ansible-vault.nvim/releases/tag/v0.3.0) - 2026-09-13

This release finishes the Create and Edit lifecycle: a successful save now ends
the protected editing session instead of leaving a plaintext buffer open beside
the file it wrote. Command arguments gain real completion, and the manual is
reachable through `:help ansible-vault` at last.

### Breaking Changes

- **BREAKING** A successful `:VaultCreate` or `:VaultEdit` save ends that
  editing session. The protected buffer is disposed and its window shows the
  durable result instead: the new ciphertext file, the refreshed whole-file
  source, or the source buffer an inline value was written back into. An inline
  edit also closes the split it opened. Previously the plaintext buffer stayed
  open for repeated saves; run `:VaultEdit` again for another edit. A failed
  save is unchanged — the buffer stays open with your changes for a retry.

### Features

- Command arguments complete from what precedes the cursor. A flag position
  offers the flags that command still accepts, minus the ones already given and
  the ones those rule out. `--vault-password-file` and
  `--new-vault-password-file` complete file names, and `:VaultCreate` completes
  its one filename until it has been given.
- `--vault-id`, `--new-vault-id` and `--encrypt-vault-id` complete vault id
  labels from the identities your project already names: the label on the
  current buffer's own ciphertext first, then `setup()`, then Ansible's
  `vault_identity_list` and `vault_encrypt_identity`. Past the `@` of a vault
  id, the source completes as a password file or a `prompt` source. Labels are
  suggestions, not a vocabulary: a new one still completes to nothing and is
  still valid to type. Completion only ever reads — it starts no child process
  and asks for no password.
- Completed paths are backslash-escaped, so a credential under a directory with
  a space in its name stays one argument.
- Whole-file `:VaultEdit` refuses to publish when the buffer it was decrypted
  from has changed, been renamed or been deleted, and no session publishes a
  result computed from text that changed while `ansible-vault` was running.

### Bug Fixes

- `:w` after `:VaultDecrypt` could refuse to save at all, reporting
  "vault.yml already exists; use :w! to overwrite it" for the very file the
  buffer was decrypted from. A bare `:w` now saves that file, and keeps it as
  the target across `:cd`; use `:w ./copy.yml` for a deliberate plaintext copy
  in the current directory.
- A buffer saved after `:VaultDecrypt` went on showing as modified until an
  unrelated event redrew it. Neovim fires none of its own write events once a
  `BufWriteCmd` handles the write, so that save now reports itself with
  `BufWritePre` and `BufWritePost`. Create and Edit saves stay silent
  deliberately: they write ciphertext elsewhere, and those events would hand a
  decrypted buffer to every formatter and linter listening for them.
- The ciphertext file a finished Create or Edit session handed back was an
  unlisted buffer: `:ls` did not mention it and `:bnext` could not return to it
  once you navigated away. It is now an ordinary listed buffer. The protected
  editing buffers go the other way and are unlisted, so they no longer appear
  beside the file they came from under the same name; `:ls!`, `<C-^>` and
  `:buffer {full-name}` still reach an unsaved one.
- Opening the file a session had written could fail with "is open with unsaved
  changes" about an unrelated buffer, because the lookup matched any buffer name
  containing that path — a neighbouring `vault.yml.bak`, or the session's own
  buffer. Names are now compared exactly.
- `:help ansible-vault` failed with E149, and so did every other tag in the
  manual. The generated `doc/tags` is now committed, so the manual works for a
  clone into 'packpath' or a checkout used directly, not only where a plugin
  manager happened to build it.
- Completion no longer offers arguments the command would then refuse: a flag
  that contradicts one already given, a second `--encrypt-vault-id` that would
  only replace the first, or a second filename for `:VaultCreate`.

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
