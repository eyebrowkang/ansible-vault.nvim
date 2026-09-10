# Contributing

## Commit messages

Release notes are generated from the commit history with
[git-cliff](https://git-cliff.org), so commit subjects must follow
[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add :VaultCreate
fix(inline): parse !vault |- block scalars
docs: document the plaintext editing mode
```

Types in use: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `ci`, `build`,
`chore`, `style`, `revert`. Append `!` or add a `BREAKING CHANGE:` footer for
incompatible changes.

### Merge strategy

The changelog has one entry per commit on the default branch, so how a pull
request is merged decides how it appears:

- **Squash** collapses the branch into one commit and the pull request title
  becomes its subject. Right for a PR that is one logical change. CI checks the
  title against the pattern above for exactly this reason.
- **Rebase** keeps every commit. Right for a branch that carries several
  independent, individually meaningful changes — squashing one of those throws
  away release notes you already wrote.

Do not use a merge commit: the merge itself is unconventional and gets filtered
out, and it adds nothing.

## Running the tests

```sh
make test        # unit tests against a fake ansible-vault, no Ansible needed
make test-real   # end-to-end against a real ansible-core in .venv (needs uv)
make test-leak   # kills Neovim mid-decryption and greps for plaintext
make lint        # stylua --check and luacheck
make format      # stylua
```

`make test` is the fast loop. `make test-real` and `make test-leak` create
`.venv/` on first run.

## Working on the privacy guarantees

Decrypted content must never reach the disk, including after a crash. A few
rules follow from that, and the tests enforce them:

- Harden a buffer **before** plaintext goes into it. Resetting `'swapfile'`
  deletes an existing swap file, so doing it afterwards is too late.
- Route every write through a `BufWriteCmd` on an `acwrite` buffer. That is what
  keeps Neovim from making a backup file or writing an undo file, and it catches
  `:w {other-file}` too.
- Never put process output into an error message. `ansible-vault decrypt` can
  write plaintext to stdout and still exit non-zero.
- Never write a secret to disk. Interactive passwords go to the child process
  through its environment, read back by a helper script that holds no secret.

If you add a code path that puts decrypted content in a buffer, add a case to
`tests/run.lua` asserting `swapfile`, `undofile` and `buftype`, and make sure
`make test-leak` still passes.

## Adding a command

Commands are declared once, in the `COMMANDS` table in
`lua/ansible-vault/init.lua`. Add an entry there; `plugin/ansible-vault.lua`
registers whatever the table contains. Then update `README.md`,
`README.zh-CN.md` and `doc/ansible-vault.txt`.
