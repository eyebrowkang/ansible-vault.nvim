.PHONY: test test-real

test:
	nvim --headless -u NONE -l tests/run.lua

.venv/bin/ansible-vault:
	uv venv .venv
	uv pip install --python .venv/bin/python ansible-core

test-real: .venv/bin/ansible-vault
	ANSIBLE_VAULT_NVIM_REAL_BIN="$(PWD)/.venv/bin/ansible-vault" nvim --headless -u NONE -l tests/real_smoke.lua
