# Contributing

Before v1.0.0, there are no compatibility or migration guarantees. Document the
current behavior, not upgrade paths; do not add compatibility aliases or migration
guides. See the [stability policy](README.md#stability-policy-before-v100).

## Commit messages

Release notes are generated from the commit history with
[git-cliff](https://git-cliff.org), so commit subjects must follow
[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add :VaultCreate
fix(inline): parse !vault |- block scalars
docs: correct the :VaultDecrypt save semantics
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
make test-leak   # kills Neovim mid-decryption, greps for unintended copies
make lint        # stylua --check and luacheck
make format      # stylua
```

`make test` is the fast loop. `make test-real` and `make test-leak` create
`.venv/` on first run.

The unit suite is a thin driver (`tests/run.lua`) over a shared harness
(`tests/helpers.lua`) and the spec files it loads. To run one test, match on its
name:

```sh
TEST_FILTER=rekey make test
```

Tests run in sorted order rather than `pairs()` order, so a failure is
reproducible: a test that only fails after some other test has run is a leak
between them, not luck.

## Working on the privacy guarantees

The goal is to prevent **unintended copies** of decrypted content, not to
prevent a save the user asked for. `:VaultDecrypt` followed by `:w` writes
plaintext on purpose; a change that "protects" the user from that is a bug, not
a hardening. A few rules follow from the distinction, and the tests enforce
them:

- Harden a buffer **before** plaintext goes into it. Resetting `'swapfile'`
  deletes an existing swap file, so doing it afterwards is too late.
- Route every write through a `BufWriteCmd` on an `acwrite` buffer. That is what
  keeps Neovim from making a backup file or writing an undo file, and it catches
  `:w {other-file}` too. What that one command then does is per session kind:
  Decrypt saves plaintext, Create and Edit encrypt.
- The rule across a plaintext/ciphertext transition is that plaintext must not
  reach the undo **file** — not that the undo history is always cleared. Either
  clear the history, or leave `'undofile'` off permanently; `[range]VaultEncrypt`
  takes the second route, so `:undo` there still recovers the value in memory.
  Also keep a buffer protected after a plaintext save — writing decrypted
  content out does not make what is still in the buffer any less decrypted. Only
  a successful whole-buffer encryption may restore normal write behaviour;
  encrypting one value proves nothing about the rest.
- Turning `'undofile'` off during the plaintext's stay does **not** make it safe
  to hand back afterwards. On the next ordinary write Neovim serializes the text
  a change *replaced*, so a buffer that was decrypted and re-encrypted in place
  would persist the plaintext into the undo file. Discard the undo history
  immediately before restoring the option, and treat that discard — not "a read
  replaced the contents" — as the thing that makes it safe: a reload is itself
  an undoable change still holding the plaintext. Where you cannot discard it,
  leave `'undofile'` off for that buffer's life and accept the loss of
  cross-session undo.
- `acwrite` does not catch everything. A partial-range write raises
  `FileWriteCmd` and an append raises `FileAppendCmd`; unhandled, Neovim writes
  those lines itself, unencrypted and not `0600`. Any buffer that can hold
  plaintext — including the read-only View window — needs those refused too.
  Shell redirection (`:w !cat > f`, `:%!tee f`) raises nothing hookable at all;
  that one is out of scope by decision, not by oversight, so do not claim the
  write paths are fully covered.
- Never put process output into an error message. `ansible-vault decrypt` can
  write plaintext to stdout and still exit non-zero.
- Never write a secret to disk. Interactive passwords go to the child process
  through its environment, read back by a helper script that holds no secret. If
  that helper is unavailable, fail closed rather than falling back to a file.
- A failed write must fail the `:w`. A `BufWriteCmd` that only notifies is
  reported as a successful write, and `:wq` would then quit with the changes
  unsaved.

If you add a code path that puts decrypted content in a buffer, add a case to
the privacy spec asserting `swapfile`, `undofile` and `buftype`, and make sure
`make test-leak` still passes. That check distinguishes a plaintext file the
user asked for from swap, undo, backup and runtime copies nobody asked for; keep
new cases on the right side of that line.

## Adding a command

Commands are declared once, in the `COMMANDS` table in
`lua/ansible-vault/init.lua`, and registered when that module loads — which is
all `plugin/ansible-vault.lua` does, and why the commands exist without
`setup()`. Add an entry to the table, give it the flag set it can actually
honour so an inapplicable flag is an error rather than a no-op, then update
`README.md`, `README.zh-CN.md` and `doc/ansible-vault.txt`.

Prefer teaching an existing verb a new scope over adding a command. Resolve its
target from the range, the buffer and the cursor, so one name covers both
whole-file and inline operations.

## Adding configuration

Think twice, then probably don't. The persistent configuration is four keys,
each named after the `ansible-vault` flag it produces. Anything that describes a
single operation rather than a standing preference — prompting for a password,
the target of a rekey — is a command argument only, because storing it as
configuration would describe a moment as if it were a setting.
