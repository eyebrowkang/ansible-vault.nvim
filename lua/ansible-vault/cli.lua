---The `ansible-vault` process boundary.
---
---Everything here is about getting bytes in and out of the child safely. Two
---rules shape it and both are load-bearing:
---
---Process output never reaches a message. `ansible-vault decrypt` can write
---plaintext to stdout and *still* exit non-zero, so a failure that quoted stdout
---would leak the secret into `:messages` and whatever backend `vim.notify` logs
---to. Only stderr and the exit code are ever reported.
---
---`vim.system` is called without `text = true`, so the bytes come back exactly as
---the child produced them. Normalizing CRLF here would quietly rewrite the line
---endings of whatever was decrypted.
---
---This module knows nothing about vault ids. Which identity to use is credential
---policy and lives in `credentials.lua`; mixing the two is how a flag ends up on
---a subcommand where it means something different.
local M = {}

local config = require("ansible-vault.config")

---How long to let `ansible-vault` run before giving up.
---
---Not configuration: an operation that takes longer than this is broken rather
---than slow, and a user-facing knob only invites tuning the symptom. The tests
---lower it to stay fast.
M.timeout_ms = 30000

---@return integer|nil
local function timeout()
  if type(M.timeout_ms) == "number" and M.timeout_ms > 0 then
    return math.floor(M.timeout_ms)
  end
  return nil
end

---Render an argv with credential values replaced.
---
---Used wherever an argv could reach the user: a vault id carries a password file
---path, and the askpass helper path is just as sensitive.
---@param argv string[]
---@return string
function M.redact_argv(argv)
  local parts = {}
  local redact_next = false
  for _, arg in ipairs(argv) do
    if redact_next then
      table.insert(parts, "<redacted>")
      redact_next = false
    else
      table.insert(parts, arg)
      redact_next = arg:match("^%-%-vault%-password%-file$") ~= nil
        or arg:match("^%-%-vault%-id$") ~= nil
        or arg:match("^%-%-new%-vault%-password%-file$") ~= nil
        or arg:match("^%-%-new%-vault%-id$") ~= nil
    end
  end
  return table.concat(parts, " ")
end

---The argv prefix that runs `ansible-vault`, honouring `ansible_vault_path`.
---
---Public because `:checkhealth` reports the executable it would actually use, and
---resolving that itself would be a second implementation that could disagree.
---@param opts? table
---@return string[]
function M.executable_argv(opts)
  local effective = config.effective(opts)
  local executable = "ansible-vault"
  if config.is_nonempty_string(effective.ansible_vault_path) then
    executable = vim.fn.expand(effective.ansible_vault_path)
  end

  return { executable }
end

---@param action string
---@param args string[]
---@param target? string|false
---@param opts? table
---@return string[]
function M.build_argv(action, args, target, opts)
  local argv = M.executable_argv(opts)
  table.insert(argv, action)
  for _, arg in ipairs(args or {}) do
    table.insert(argv, tostring(arg))
  end
  if target == nil then
    target = "-"
  end
  if target ~= false then
    table.insert(argv, tostring(target))
  end
  return argv
end

---@param output string
---@return string[]
function M.output_to_lines(output)
  if output == "" then
    return { "" }
  end
  return vim.split(output, "\n", { plain = true })
end

---Describe a failed run without echoing the process output.
---@param action string
---@param exit_code integer
---@param stderr string
---@return string
local function failure_message(action, exit_code, stderr)
  if stderr ~= "" then
    return stderr
  end
  return string.format("ansible-vault %s exited with status %d", action, exit_code)
end

---Spawn `ansible-vault` and hand the result to `callback`.
---
---`vim.system` enforces the timeout itself and reports exit code 124 when it
---fires, so there is no timer to arm, cancel or leak. It also merges `env` into
---the inherited environment rather than replacing it, which is what lets the
---password be passed through `ANSIBLE_VAULT_NVIM_PASSWORD` without stripping
---`PATH` from the child.
---@param action string
---@param args string[]
---@param opts table|nil
---@param creds AnsibleVaultCredentials|nil
---@param stdin string|nil Content to pipe in, or nil when operating on a file
---@param file string|nil File to operate on, or nil when piping stdin
---@param callback fun(success: boolean, output: string)
local function spawn(action, args, opts, creds, stdin, file, callback)
  local argv = M.build_argv(action, args or {}, file or "-", opts)

  local budget = timeout()
  local system_opts = {
    cwd = creds and creds.cwd or nil,
    env = creds and creds.env or nil,
    timeout = budget,
    stdin = stdin,
  }

  -- Deliberately not `text = true`: that would normalize CRLF in the output,
  -- rewriting the line endings of whatever was decrypted.
  local ok, err = pcall(vim.system, argv, system_opts, function(result)
    vim.schedule(function()
      if result.code == 0 then
        callback(true, result.stdout or "")
      elseif result.code == 124 then
        callback(false, string.format("ansible-vault %s timed out after %dms", action, budget or 0))
      else
        callback(false, failure_message(action, result.code, result.stderr or ""))
      end
    end)
  end)

  if not ok then
    -- `err` can quote the argv back, which carries vault ids and the askpass
    -- helper path, so it goes through the same redaction as everything else.
    callback(false, "Failed to start ansible-vault: " .. M.redact_argv({ tostring(err) }))
  end
end

---Run `ansible-vault` over content piped on stdin.
---@param action string The vault action (encrypt, decrypt, encrypt_string)
---@param input string Input content
---@param args string[] Additional arguments
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
---@param creds? AnsibleVaultCredentials Supplies the child cwd and environment
function M.run(action, input, args, callback, opts, creds)
  spawn(action, args, opts, creds, input, nil, callback)
end

---Run `ansible-vault` against a file path.
---@param action string
---@param file_path string
---@param args string[]
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
---@param creds? AnsibleVaultCredentials
function M.run_file(action, file_path, args, callback, opts, creds)
  spawn(action, args, opts, creds, nil, file_path, callback)
end

return M
