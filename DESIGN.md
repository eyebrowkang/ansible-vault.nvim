# Design notes

This is the only file here written for people **changing** the plugin.
`README.md`, `README.zh-CN.md` and `doc/ansible-vault.txt` are written for
people **using** it: they describe behaviour and never justify it. Keep that
split — reasoning belongs in this file or in a comment next to the code it
explains.

The code already says what the plugin does, and this file does not repeat it.
What it records is what the code cannot: the order in which goals win, what is
deliberately absent, and the rules that have to survive a refactor.

## The priority order

1. **Privacy.** No plaintext copy the user did not ask for.
2. **The core `ansible-vault` capabilities**, for whole files and for inline
   YAML `!vault` values alike.
3. **Nothing else, before v1.0.0.**

These are ranked, not balanced. Where 1 and 2 conflict, 1 wins and the
operation fails: a buffer that cannot be hardened keeps its ciphertext, and an
interactive password that cannot be handed to the child process safely stops
the operation rather than falling back to a file. A refused operation is
recoverable; a leaked secret is not.

## What privacy means here

The threat is a copy **nobody asked for** — a swap file, a persistent undo
file, a backup, an editor temporary file, crash residue, a password on disk.

It is **not** a plaintext file the user deliberately wrote. `:VaultDecrypt`
followed by `:w` saves plaintext on purpose. An earlier design had that write
silently re-encrypt, and it was rejected: it made a command mean something
other than its name. A verb that lies is worse for security than an honest
plaintext save, because the user can reason about the second and not about the
first.

So the question when hardening anything is not "could plaintext reach the disk
here?" but "did the user ask for this copy?". Never answer the first question
by overriding a save that answers the second.

### Rules that must survive a refactor

How each of these works is explained where it is implemented, mostly in
`secure.lua` and `plaintext.lua`. What those comments cannot tell you is that
every rule below is standing on a bug that already happened. They are
invariants, not preferences.

- Global options are **warned about, never changed**. `'shada'`, `'backup'`
  and `'writebackup'` are the user's; `:checkhealth` reports the risk. Do not
  "fix" this by mutating globals.
- A password is **never written to a file**. If the helper cannot be
  installed, the operation fails. A file that is "removed on exit" is still a
  file a crash leaves behind.
- No history tracking, sidecar metadata or database remembering that a file
  used to be a vault. A plaintext file the user saved and reopens later is
  just a file, and treating it as anything else re-introduces the copy this
  plugin exists to avoid.
- Shell redirection (`:w !cat > f`, `:%!tee f`) raises nothing this plugin can
  hook, and is out of scope **by decision** — it is an explicit instruction
  from the user, like yanking with `'shada'` on. Do not let the documentation
  claim the write paths are fully covered.
- `make test-leak` is the regression guard, and a leak test that has never
  failed is not known to work. If you change it, first confirm it still fails
  against a deliberately broken build, and keep it distinguishing the
  plaintext the user asked for from copies they did not.

## Scope: capability, not CLI parity

The native `ansible-vault` subcommands define the **capabilities** that must
work. They do not define the command surface; this plugin is not a front-end
for the binary.

That `create`, `edit` and `view` are implemented in the editor instead of by
calling the matching subcommands is not incidental. Those subcommands need a
tty, launch `$EDITOR`, and route plaintext through a temporary file — which
the first priority forbids outright.

Both lifecycles are first class. A change that works for whole files but not
for inline values, or the reverse, is half a change.

### Declined before v1.0.0

Decisions, not gaps. An absent feature leaves no trace in the code, so they
are listed here to keep them from being re-added as oversights:

- A statusline integration, or any buffer variable published to support one.
- A public Lua API beyond `setup()`. `require("ansible-vault")` exports
  `setup` and nothing else; the six commands are the interface. An API that
  lets other code decrypt without the user asking for it is surface this
  plugin cannot stand behind.
- An event protocol announcing which secret was operated on.
- File pickers, vault-file scanners, and git or diff integration.
- Batch operations across multiple files.

Before adding anything, name the lifecycle it completes — whole-file or
inline. If it completes neither, it is a conversation for v1.0.0 or later, and
that conversation is with the maintainer, not with a test that would like the
feature to exist.

## Compatibility

Before v1.0.0 there are **no compatibility or migration guarantees**. Document
current behaviour; do not write upgrade paths, deprecation aliases or
migration shims. A removed option should report itself as unknown, which
`setup()` already does, instead of quietly continuing to work.

The plugin tracks the **current Neovim release only** — see
`MIN_NVIM_VERSION` in `config.lua`. Do not add `vim.fn.has("nvim-0.x")`
branches or fallbacks for APIs the current release provides; prefer the newest
API whenever it deletes code. Platform guards are not version guards and stay.

## Tests

What the suites are and how they differ is described in their own headers.
Two conventions are not visible there:

- Assert what a user would notice — a write refused, a file left alone, an
  operation that still works afterwards — rather than internal fields, session
  objects or autocmd counts. A test bound to internals blocks refactors it was
  never about, and it can keep passing while the behaviour it was meant to
  protect breaks.
- Cover ordinary use and the mistakes that come with it. Exhaustive
  combinations of injected failures cost more to maintain than they ever find.
