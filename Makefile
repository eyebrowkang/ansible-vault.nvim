.PHONY: all check test test-env test-real test-leak lint format changelog release-notes check-version

all: lint test

check: lint test test-real test-leak

test:
	nvim --headless -u NONE -l tests/run.lua

# Reuse the environment, but apply the same test baseline on every machine.
test-env: .python-version tests/requirements.txt
	@if [ ! -e .venv ]; then uv venv --python "$$(tr -d '\r\n' < .python-version)" .venv; fi
	@test -x .venv/bin/python || { printf '%s\n' '.venv is not a usable Python environment; move it aside and retry.' >&2; exit 1; }
	@.venv/bin/python -c 'import pathlib, platform, sys; expected = pathlib.Path(".python-version").read_text().strip(); sys.exit(0 if platform.python_version() == expected else "Test Python must be " + expected + "; move .venv aside and rerun make test-env.")'
	uv pip install --python .venv/bin/python -r tests/requirements.txt

test-real: test-env
	ANSIBLE_VAULT_NVIM_REAL_BIN="$(CURDIR)/.venv/bin/ansible-vault" nvim --headless -u NONE -l tests/real_smoke.lua

# Kills Neovim with decrypted content and checks for unintended disk copies.
test-leak: test-env
	ANSIBLE_VAULT_NVIM_REAL_BIN="$(CURDIR)/.venv/bin/ansible-vault" tests/crash_leak.sh

lint:
	stylua --check .
	luacheck lua/ plugin/ tests/

format:
	stylua .

VERSION_NAME = $(VERSION:v%=%)

check-version:
	@printf '%s\n' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$$' || { printf '%s\n' 'Usage: make <target> VERSION=vX.Y.Z' >&2; exit 1; }

# git-cliff creates a draft. Curate, review and commit it before creating the tag.
changelog: check-version
	@if grep -Fq '## [$(VERSION_NAME)]' CHANGELOG.md; then printf '%s\n' 'This version is already in CHANGELOG.md; review its existing entry.' >&2; exit 1; fi
	git-cliff --config cliff.toml --unreleased --tag "$(VERSION)" --prepend CHANGELOG.md

# Print the curated body for one release. GitHub supplies the release title.
release-notes: check-version
	@awk -v heading="## [$(VERSION_NAME)](https://github.com/eyebrowkang/ansible-vault.nvim/releases/tag/$(VERSION)) - " -f tools/release-notes.awk CHANGELOG.md
