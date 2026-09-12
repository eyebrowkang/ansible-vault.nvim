#!/usr/bin/env python3
"""Byte-exact process double, not a cryptographic oracle.

What it is faithful about: bytes. It consumes every credential source it is given
(including executing an askpass helper), verifies that the password it was handed
matches the one an envelope was sealed with, and never adds or strips a newline
around plaintext.

What it deliberately does NOT model: Ansible's secret *precedence*. Real
ansible-vault builds its pool from DEFAULT_VAULT_IDENTITY_LIST before the
--vault-id flags, which is the whole reason `credentials.identity_list_env`
exists; reproducing that from memory would make this file an authority on
something it only guesses at. Here CLI flags win and ansible.cfg is a fallback.
Precedence, and every claim about which password a file actually ends up under,
is verified against the real binary in tests/real_smoke.lua.
"""
import configparser
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def log(text):
    if os.environ.get("FAKE_VAULT_LOG"):
        with open(os.environ["FAKE_VAULT_LOG"], "a", encoding="utf-8") as stream:
            stream.write(text + "\n")


#: Reported so a test can assert on the environment the child really received.
#: The password variable is reported as set/unset only: logging its value would
#: put the secret in a file, which is the thing these tests are checking for.
LOGGED_ENV = (
    "ANSIBLE_ASK_VAULT_PASS",
    "ANSIBLE_CONFIG",
    "ANSIBLE_VAULT_ENCRYPT_IDENTITY",
    "ANSIBLE_VAULT_IDENTITY",
    "ANSIBLE_VAULT_IDENTITY_LIST",
    "ANSIBLE_VAULT_PASSWORD_FILE",
)


def log_environment():
    for name in LOGGED_ENV:
        if name in os.environ:
            log("ENV:" + name + "=" + os.environ[name])
    if os.environ.get("ANSIBLE_VAULT_NVIM_PASSWORD"):
        log("ENVPW:set")


def password(source):
    path = Path(source).expanduser()
    if os.access(path, os.X_OK):
        result = subprocess.run([str(path)], capture_output=True, check=True)
        value = result.stdout.rstrip(b"\r\n")
    else:
        value = path.read_bytes().rstrip(b"\r\n")
    if not value:
        raise ValueError("empty credential")
    log("CONSUMED")
    return value


def envelope(value, secret, label="default", nonce=0):
    header = "$ANSIBLE_VAULT;1.1;AES256"
    if label and label != "default":
        header = "$ANSIBLE_VAULT;1.2;AES256;" + label
    payload = json.dumps({"value": value.hex(), "password": hashlib.sha256(secret).hexdigest(), "nonce": nonce})
    return (header + "\n" + payload.encode().hex() + "\n").encode()


def decode(data, secrets):
    lines = data.decode().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("$ANSIBLE_VAULT;"))
    payload = json.loads(bytes.fromhex("".join(line.strip() for line in lines[start + 1:])).decode())
    if payload["password"] not in [hashlib.sha256(secret).hexdigest() for _, secret in secrets]:
        raise ValueError("wrong password")
    return bytes.fromhex(payload["value"])


def main():
    args = sys.argv[1:]
    log("CALL")
    log("CWD:" + os.getcwd())
    log_environment()
    for arg in args:
        log("ARG:" + arg)
    action = args.pop(0)
    log("ACTION:" + action)
    config = configparser.ConfigParser(interpolation=None)
    cfg_path = os.environ.get("ANSIBLE_CONFIG", "ansible.cfg")
    config.read(cfg_path)
    defaults = config["defaults"] if config.has_section("defaults") else {}
    sources, new_sources = [], []
    name, label, target = "encrypted_string", None, "-"
    while args:
        arg = args.pop(0)
        if arg in ("--vault-id", "--new-vault-id"):
            identity = args.pop(0)
            identity_label, source = identity.split("@", 1)
            (new_sources if arg.startswith("--new") else sources).append((identity_label, source))
        elif arg in ("--vault-password-file", "--new-vault-password-file"):
            (new_sources if arg.startswith("--new") else sources).append(("default", args.pop(0)))
        elif arg == "--encrypt-vault-id":
            label = args.pop(0)
        elif arg == "--stdin-name":
            name = args.pop(0)
        elif arg == "--output":
            if args.pop(0) != "-":
                raise ValueError("the fake only supports stdout output")
        elif arg.startswith("--"):
            raise ValueError("unsupported fake flag")
        else:
            target = arg
    if not sources:
        src = os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE", defaults.get("vault_password_file", ""))
        if src:
            sources.append(("default", src))
        ids = os.environ.get("ANSIBLE_VAULT_IDENTITY_LIST", defaults.get("vault_identity_list", ""))
        for identity in filter(None, (item.strip() for item in ids.split(","))):
            identity_label, src = identity.split("@", 1)
            sources.append((identity_label, src))
    secrets = [(identity, password(src)) for identity, src in sources]
    if not secrets:
        raise ValueError("no credential was consumed")
    selected = next((item for item in secrets if item[0] == label), secrets[0])
    label = label or selected[0]
    data = Path(target).read_bytes() if action == "rekey" else sys.stdin.buffer.read()
    if os.environ.get("FAKE_VAULT_STDIN_LOG"):
        Path(os.environ["FAKE_VAULT_STDIN_LOG"]).write_bytes(data)
    if os.environ.get("FAKE_VAULT_SLEEP"):
        time.sleep(float(os.environ["FAKE_VAULT_SLEEP"]))
    applies = os.environ.get("FAKE_VAULT_ACTION", action) == action
    if os.environ.get("FAKE_VAULT_FAIL") and applies:
        if action == "rekey":
            Path(target).write_bytes(b"damaged staging file")
        sys.stdout.write("PRIVATE-STDOUT-CANARY")
        sys.stderr.write("PRIVATE-STDERR-CANARY " + os.environ["FAKE_VAULT_FAIL"])
        return 1
    mode = os.environ.get("FAKE_VAULT_OUTPUT") if applies else None
    if mode:
        result = {"invalid": b"PRIVATE-BAD-OUTPUT", "empty": b"", "truncated": b"$ANSIBLE_VAULT;1.1;AES256\n", "noop": data}[mode]
        if action == "rekey":
            Path(target).write_bytes(result)
        else:
            sys.stdout.buffer.write(result)
        return 0
    if action == "decrypt":
        sys.stdout.buffer.write(decode(data, secrets))
    elif action == "encrypt":
        sys.stdout.buffer.write(envelope(data, selected[1], label))
    elif action == "encrypt_string":
        encrypted = envelope(data, selected[1], label).decode()
        sys.stdout.write(name + ": !vault |\n" + "".join("          " + line + "\n" for line in encrypted.splitlines()))
    elif action == "rekey":
        value = decode(data, secrets)
        if len(new_sources) != 1:
            raise ValueError("exactly one new credential required")
        new_label, src = new_sources[0]
        Path(target).write_bytes(envelope(value, password(src), new_label, nonce=1))
    else:
        raise ValueError("unsupported fake action")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.stderr.write("fake vault failed to consume credentials or parse input\n")
        sys.exit(2)
