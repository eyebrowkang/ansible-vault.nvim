#!/usr/bin/env bash
#
# Kill Neovim while a vault file is decrypted, then search every place Neovim
# could have persisted the buffer for the plaintext.
#
# Headless Neovim sets 'updatecount' to 0, which disables swap files entirely,
# so the harness turns it back on. Without that this test passes for the wrong
# reason.
#
# Usage: tests/crash_leak.sh [path-to-plugin-root]

set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VAULT_BIN="${ANSIBLE_VAULT_NVIM_REAL_BIN:-$ROOT/.venv/bin/ansible-vault}"
SECRET="CANARY-9f2b41d7-PLAINTEXT"

if [ ! -x "$VAULT_BIN" ]; then
  echo "real ansible-vault binary is not executable: $VAULT_BIN" >&2
  echo "run 'make test-real' once to create it" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

STATE="$WORK/state"
mkdir -p "$STATE/swap" "$STATE/undo" "$STATE/run"

printf 'vaultsecret\n' > "$WORK/pass"
chmod 600 "$WORK/pass"
printf 'api_key: %s\n' "$SECRET" > "$WORK/vault.yml"
"$VAULT_BIN" encrypt --vault-password-file "$WORK/pass" "$WORK/vault.yml" >/dev/null 2>&1

cat > "$WORK/decrypt.lua" <<LUA
vim.opt.runtimepath:prepend("$ROOT")
vim.o.updatecount = 200
vim.o.directory = "$STATE/swap//"
vim.o.undodir = "$STATE/undo"
vim.o.undofile = true
vim.o.swapfile = true

require("ansible-vault").setup({
  ansible_vault_path = "$VAULT_BIN",
  password_file = "$WORK/pass",
  auto_detect = true,
  notify_success = false,
})

vim.cmd("edit $WORK/vault.yml")
local buf = vim.api.nvim_get_current_buf()
require("ansible-vault").decrypt(buf)

vim.wait(15000, function()
  return (vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] or ""):find("$SECRET", 1, true) ~= nil
end, 20)

-- Touch the buffer so Neovim has every reason to flush it to the swap file.
vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "extra: line" })
vim.cmd("silent! preserve")
io.stdout:write("DECRYPTED\n")
io.stdout:flush()
vim.wait(60000)
LUA

XDG_RUNTIME_DIR="$STATE/run" nvim --headless -u NONE -l "$WORK/decrypt.lua" > "$WORK/out" 2>&1 &
NVIM_PID=$!

for _ in $(seq 1 150); do
  grep -q DECRYPTED "$WORK/out" 2>/dev/null && break
  sleep 0.1
done

if ! grep -q DECRYPTED "$WORK/out" 2>/dev/null; then
  echo "FAIL: the file never decrypted; harness output:" >&2
  cat "$WORK/out" >&2
  kill -9 "$NVIM_PID" 2>/dev/null
  exit 2
fi

kill -9 "$NVIM_PID" 2>/dev/null
wait "$NVIM_PID" 2>/dev/null

status=0
report() {
  local label="$1" dir="$2"
  if [ ! -d "$dir" ]; then
    echo "  ok   $label: nothing was created"
    return
  fi
  local hits
  hits="$(grep -rl "$SECRET" "$dir" 2>/dev/null)"
  if [ -n "$hits" ]; then
    echo "  LEAK $label:"
    echo "$hits" | sed 's/^/         /'
    status=1
  else
    echo "  ok   $label: no plaintext ($(find "$dir" -type f | wc -l | tr -d ' ') files)"
  fi
}

echo "After SIGKILL with the file decrypted:"
report "swap files" "$STATE/swap"
report "undo files" "$STATE/undo"
report "runtime dir" "$STATE/run"

if grep -q "$SECRET" "$WORK/vault.yml" 2>/dev/null; then
  echo "  LEAK the vault file itself now holds plaintext"
  status=1
else
  echo "  ok   the vault file on disk is still ciphertext"
fi

leftover="$(find "$STATE/run" -type f 2>/dev/null | xargs grep -l vaultsecret 2>/dev/null)"
if [ -n "$leftover" ]; then
  echo "  LEAK vault password left behind:"
  echo "$leftover" | sed 's/^/         /'
  status=1
else
  echo "  ok   no vault password left behind"
fi

if [ "$status" -eq 0 ]; then
  echo "CRASH_LEAK_OK"
else
  echo "CRASH_LEAK_FAILED" >&2
fi
exit "$status"
