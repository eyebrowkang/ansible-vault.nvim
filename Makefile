.PHONY: all test test-real test-leak lint format

all: lint test

test:
	nvim --headless -u NONE -l tests/run.lua

.venv/bin/ansible-vault:
	uv venv .venv
	uv pip install --python .venv/bin/python ansible-core

test-real: .venv/bin/ansible-vault
	ANSIBLE_VAULT_NVIM_REAL_BIN="$(PWD)/.venv/bin/ansible-vault" nvim --headless -u NONE -l tests/real_smoke.lua

# Kills Neovim with a vault file decrypted and searches Neovim's swap, undo and
# runtime directories for the plaintext.
test-leak: .venv/bin/ansible-vault
	ANSIBLE_VAULT_NVIM_REAL_BIN="$(PWD)/.venv/bin/ansible-vault" tests/crash_leak.sh

lint:
	stylua --check .
	luacheck lua/ plugin/ tests/

format:
	stylua .
