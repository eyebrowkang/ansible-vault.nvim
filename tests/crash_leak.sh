#!/usr/bin/env bash
#
# Kill Neovim with decrypted content in it, then search every place Neovim or the
# plugin could have left a copy behind.
#
# What counts as a leak here is the point of the script. `:VaultDecrypt` followed
# by `:w` is how you decrypt a file, so plaintext at the target the user asked
# for is the intended result, not a finding. A leak is a copy the user never
# asked for: a swap file, a persistent undo file, a backup, a temporary file, or
# a password left in the runtime directory.
#
# Headless Neovim sets 'updatecount' to 0, which disables swap files entirely, so
# each scenario turns it back on. Without that these checks pass for the wrong
# reason.
#
# Usage: tests/crash_leak.sh [path-to-plugin-root]

set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VAULT_BIN="${ANSIBLE_VAULT_NVIM_REAL_BIN:-$ROOT/.venv/bin/ansible-vault}"
SECRET="CANARY-9f2b41d7-PLAINTEXT"
PASSWORD="vaultsecret-6a1e"

if [ ! -x "$VAULT_BIN" ]; then
  echo "real ansible-vault binary is not executable: $VAULT_BIN" >&2
  echo "run 'make test-real' once to create it" >&2
  exit 2
fi

BASE="$(mktemp -d)"
trap 'chmod -R u+rwX "$BASE" 2>/dev/null; rm -rf "$BASE"' EXIT

status=0

# ---------------------------------------------------------------------------

# Search a directory for a needle, reporting the files that matched.
scan() {
  local label="$1" needle="$2" dir="$3"
  if [ ! -d "$dir" ]; then
    echo "    ok   $label: nothing was created"
    return
  fi
  local hits
  hits="$(grep -rl -- "$needle" "$dir" 2>/dev/null)"
  if [ -n "$hits" ]; then
    echo "    LEAK $label:"
    echo "$hits" | sed 's/^/           /'
    status=1
  else
    echo "    ok   $label: clean ($(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ') files)"
  fi
}

# Assert a needle IS present, for the copies the user explicitly asked for.
#
# Both of these fail on a missing file rather than treating it as a clean pass:
# a grep against a path that does not exist reports "no match" and would make
# either check succeed for the wrong reason.
expect_present() {
  local label="$1" needle="$2" file="$3"
  if [ ! -f "$file" ]; then
    echo "    FAIL $label: $file does not exist"
    status=1
  elif grep -q -- "$needle" "$file" 2>/dev/null; then
    echo "    ok   $label"
  else
    echo "    FAIL $label: expected content is missing from $file"
    status=1
  fi
}

expect_absent() {
  local label="$1" needle="$2" file="$3"
  if [ ! -f "$file" ]; then
    echo "    FAIL $label: $file does not exist"
    status=1
  elif grep -q -- "$needle" "$file" 2>/dev/null; then
    echo "    FAIL $label: $file holds it"
    status=1
  else
    echo "    ok   $label"
  fi
}

# Run one scenario: build a fresh state tree, run the given Lua until it prints
# READY, then either SIGKILL it (crash) or let it exit (clean).
#
# $1 scenario name, $2 "crash"|"clean", $3 Lua body
run_scenario() {
  local name="$1" mode="$2" body="$3"
  # WORK stays global on purpose: the caller checks the scenario's own files
  # afterwards, and recomputing the path is how a check ends up grepping
  # something that was never there.
  WORK="$BASE/$(printf '%s' "$name" | tr -c 'a-zA-Z0-9' '_')"
  STATE="$WORK/state"
  mkdir -p "$STATE/swap" "$STATE/undo" "$STATE/backup" "$STATE/run" "$STATE/tmp"

  printf '%s\n' "$PASSWORD" > "$WORK/pass"
  chmod 600 "$WORK/pass"
  printf 'api_key: %s\n' "$SECRET" > "$WORK/vault.yml"
  "$VAULT_BIN" encrypt --vault-password-file "$WORK/pass" "$WORK/vault.yml" >/dev/null 2>&1

  cat > "$WORK/scenario.lua" <<LUA
vim.opt.runtimepath:prepend("$ROOT")
vim.o.updatecount = 200
vim.o.directory = "$STATE/swap//"
vim.o.undodir = "$STATE/undo"
vim.o.backupdir = "$STATE/backup"
vim.o.undofile = true
vim.o.swapfile = true
vim.o.backup = true
vim.o.hidden = true

require("ansible-vault").setup({
  ansible_vault_path = "$VAULT_BIN",
  password_files = "$WORK/pass",
})

local WORK = "$WORK"
local SECRET = "$SECRET"

local function wait_for(predicate)
  return vim.wait(20000, predicate, 20)
end

local function holds_secret(buf)
  local text = table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n")
  return text:find(SECRET, 1, true) ~= nil
end

$body

-- Give Neovim every reason to flush the buffer to disk before it dies.
vim.cmd("silent! preserve")
io.stdout:write("READY\n")
io.stdout:flush()
vim.wait(60000)
LUA

  echo "  $name:"
  (
    cd "$WORK" || exit 1
    XDG_RUNTIME_DIR="$STATE/run" TMPDIR="$STATE/tmp" \
      nvim --headless -u NONE -l "$WORK/scenario.lua" > "$WORK/out" 2>&1 &
    echo $! > "$WORK/pid"
    wait "$(cat "$WORK/pid")" 2>/dev/null
  ) &
  local runner=$!

  local pid=""
  for _ in $(seq 1 300); do
    [ -f "$WORK/pid" ] && pid="$(cat "$WORK/pid" 2>/dev/null)"
    grep -q READY "$WORK/out" 2>/dev/null && break
    sleep 0.1
  done

  if ! grep -q READY "$WORK/out" 2>/dev/null; then
    echo "    FAIL the scenario never reached READY; output:"
    sed 's/^/           /' "$WORK/out" 2>/dev/null
    status=1
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    wait "$runner" 2>/dev/null
    return
  fi

  if [ "$mode" = "crash" ]; then
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  else
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
    sleep 0.3
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  fi
  wait "$runner" 2>/dev/null

  scan "swap files" "$SECRET" "$STATE/swap"
  scan "undo files" "$SECRET" "$STATE/undo"
  scan "backup files" "$SECRET" "$STATE/backup"
  scan "runtime dir" "$SECRET" "$STATE/run"
  scan "temp dir" "$SECRET" "$STATE/tmp"
  scan "password in runtime dir" "$PASSWORD" "$STATE/run"
  scan "password in temp dir" "$PASSWORD" "$STATE/tmp"
}

# ---------------------------------------------------------------------------

echo "Plaintext residue after SIGKILL:"

# 1. The plaintext is in the buffer and was never saved. Nothing on disk may
#    hold it, including the vault file itself.
run_scenario "decrypted buffer, never saved" crash '
vim.cmd("silent edit " .. WORK .. "/vault.yml")
local buf = vim.api.nvim_get_current_buf()
vim.cmd("VaultDecrypt")
assert(wait_for(function() return holds_secret(buf) end), "decrypt never finished")
vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "extra: line" })
'
expect_absent "the vault file on disk is still ciphertext" "$SECRET" "$WORK/vault.yml"

# 2. A read-only View float. Nothing it shows may reach the disk, and it must not
#    stage the plaintext in a temporary file to get it there.
run_scenario "View float open" crash '
vim.cmd("silent edit " .. WORK .. "/vault.yml")
vim.cmd("VaultView")
assert(wait_for(function()
  return holds_secret(vim.api.nvim_get_current_buf())
end), "view never opened")
'
expect_absent "View left the vault file alone" "$SECRET" "$WORK/vault.yml"

# 3. An Edit scratch with unsaved plaintext in it.
run_scenario "Edit scratch with unsaved changes" crash '
vim.cmd("silent edit " .. WORK .. "/vault.yml")
local source = vim.api.nvim_get_current_buf()
vim.cmd("VaultEdit")
assert(wait_for(function() return vim.api.nvim_get_current_buf() ~= source end), "edit never opened")
local scratch = vim.api.nvim_get_current_buf()
assert(holds_secret(scratch), "the scratch should hold the decrypted file")
vim.api.nvim_buf_set_lines(scratch, -1, -1, false, { "more: " .. SECRET })
'
expect_absent "Edit left the vault file alone" "$SECRET" "$WORK/vault.yml"

# 4. A Create buffer that was never written.
run_scenario "Create buffer never written" crash '
vim.cmd("VaultCreate " .. WORK .. "/created.yml")
vim.api.nvim_buf_set_lines(0, 0, -1, false, { "api_key: " .. SECRET })
'

# 5. The explicit decrypt-and-save path. The target file is SUPPOSED to hold the
#    plaintext afterwards; everything else still must not.
run_scenario "explicit Decrypt then save" crash '
vim.cmd("silent edit " .. WORK .. "/vault.yml")
local buf = vim.api.nvim_get_current_buf()
vim.cmd("VaultDecrypt")
assert(wait_for(function() return holds_secret(buf) end), "decrypt never finished")
vim.cmd("silent write")
'
expect_present "the file the user explicitly saved holds the plaintext, as asked" "$SECRET" "$WORK/vault.yml"

# 6. Decrypt, re-encrypt, then save. Only ciphertext was ever asked for, so no
#    copy of the plaintext may be left anywhere.
run_scenario "Decrypt then Encrypt then save" crash '
vim.cmd("silent edit " .. WORK .. "/vault.yml")
local buf = vim.api.nvim_get_current_buf()
vim.cmd("VaultDecrypt")
assert(wait_for(function() return holds_secret(buf) end), "decrypt never finished")
vim.cmd("VaultEncrypt")
assert(wait_for(function() return not holds_secret(buf) end), "re-encrypt never finished")
vim.cmd("silent write")
'
expect_absent "the re-encrypted file holds no plaintext" "$SECRET" "$WORK/vault.yml"

# 7. Abandoning a decrypt by reloading the file. The only thing ever asked for
#    was ciphertext, so no copy of the plaintext may survive — including in the
#    undo state the reload leaves behind.
run_scenario "Decrypt then reload then save" crash '
vim.cmd("silent edit " .. WORK .. "/vault.yml")
local buf = vim.api.nvim_get_current_buf()
vim.cmd("VaultDecrypt")
assert(wait_for(function() return holds_secret(buf) end), "decrypt never finished")
vim.cmd("silent! edit!")
assert(not holds_secret(buf), "the reload should have replaced the plaintext")
vim.api.nvim_buf_set_lines(buf, -1, -1, false, { "6161" })
vim.cmd("silent write")
'
expect_absent "the reloaded file holds no plaintext" "$SECRET" "$WORK/vault.yml"

# 8. An interactive password must not be written anywhere, and the helper script
#    that carries it must contain no secret of its own.
echo "  interactive password residue:"
IWORK="$BASE/interactive"
mkdir -p "$IWORK/run" "$IWORK/tmp"
printf 'api_key: %s\n' "$SECRET" > "$IWORK/vault.yml"
printf '%s\n' "$PASSWORD" > "$IWORK/pass"
chmod 600 "$IWORK/pass"
"$VAULT_BIN" encrypt --vault-password-file "$IWORK/pass" "$IWORK/vault.yml" >/dev/null 2>&1
cat > "$IWORK/interactive.lua" <<LUA
vim.opt.runtimepath:prepend("$ROOT")
require("ansible-vault").setup({ ansible_vault_path = "$VAULT_BIN" })
vim.fn.inputsecret = function() return "$PASSWORD" end
vim.cmd("silent edit $IWORK/vault.yml")
local buf = vim.api.nvim_get_current_buf()
vim.cmd("VaultDecrypt")
local ok = vim.wait(20000, function()
  return (vim.api.nvim_buf_get_lines(buf, 0, 1, false)[1] or ""):find("$SECRET", 1, true) ~= nil
end, 20)
io.stdout:write(ok and "TYPED_OK\n" or "TYPED_FAILED\n")
io.stdout:flush()
LUA
XDG_RUNTIME_DIR="$IWORK/run" TMPDIR="$IWORK/tmp" \
  nvim --headless -u NONE -l "$IWORK/interactive.lua" > "$IWORK/out" 2>&1
if grep -q TYPED_OK "$IWORK/out"; then
  echo "    ok   a typed password decrypted the file"
else
  echo "    FAIL the typed password never decrypted the file; output:"
  sed 's/^/           /' "$IWORK/out"
  status=1
fi
scan "typed password in runtime dir" "$PASSWORD" "$IWORK/run"
scan "typed password in temp dir" "$PASSWORD" "$IWORK/tmp"
scan "plaintext in runtime dir" "$SECRET" "$IWORK/run"
helper="$IWORK/run/ansible-vault.nvim/askpass.sh"
if [ -f "$helper" ]; then
  perm="$(stat -c '%a' "$helper" 2>/dev/null || stat -f '%Lp' "$helper")"
  if [ "$perm" = "700" ]; then
    echo "    ok   the password helper is owner-only ($perm)"
  else
    echo "    FAIL the password helper is mode $perm"
    status=1
  fi
else
  echo "    ok   no password helper was installed"
fi

if [ "$status" -eq 0 ]; then
  echo "CRASH_LEAK_OK"
else
  echo "CRASH_LEAK_FAILED" >&2
fi
exit "$status"
