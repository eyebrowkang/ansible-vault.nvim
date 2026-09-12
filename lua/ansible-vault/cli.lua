---The `ansible-vault` process boundary.
---
---Everything here is about getting bytes in and out of the child safely. Three
---rules shape it and all of them are load-bearing:
---
---Process output never reaches a message. `ansible-vault decrypt` can write
---plaintext to stdout and *still* exit non-zero, so a failure that quoted stdout
---would leak the secret into `:messages` and whatever backend `vim.notify` logs
---to. A failure reports the exit code and a redacted, length-capped summary of
---stderr — never stdout, never the argv, never the child's environment, and never
---a raw spawn exception, which quotes the argv back.
---
---`vim.system` is called without `text = true`, so the bytes come back exactly as
---the child produced them. Normalizing CRLF here would quietly rewrite the line
---endings of whatever was decrypted.
---
---This module knows nothing about *which* identity to use — that is credential
---policy and lives in `credentials.lua`. It does apply the per-subcommand
---environment that module publishes, because the one case that needs it, `rekey`,
---fails silently rather than loudly when it is forgotten.
local M = {}

local config = require("ansible-vault.config")
local credentials = require("ansible-vault.credentials")

---How long to let `ansible-vault` run before giving up.
---
---Not configuration: an operation that takes longer than this is broken rather
---than slow, and a user-facing knob only invites tuning the symptom. The tests
---lower it to stay fast.
M.timeout_ms = 30000

---Upper bound on a reported failure, so a chatty child cannot flood `:messages`.
local MAX_MESSAGE = 500

---Flags whose *value* is a credential: a password file path, or a vault id
---carrying one.
local CREDENTIAL_FLAGS = {
  ["--vault-password-file"] = true,
  ["--vault-id"] = true,
  ["--new-vault-password-file"] = true,
  ["--new-vault-id"] = true,
}

---@return integer|nil
local function timeout()
  if type(M.timeout_ms) == "number" and M.timeout_ms > 0 then
    return math.floor(M.timeout_ms)
  end
  return nil
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

---@param text string
---@param needle string
---@param replacement string
---@return string
local function replace_plain(text, needle, replacement)
  if needle == "" then
    return text
  end
  local parts, index = {}, 1
  while true do
    local first, last = text:find(needle, index, true)
    if not first then
      break
    end
    table.insert(parts, text:sub(index, first - 1))
    table.insert(parts, replacement)
    index = last + 1
  end
  table.insert(parts, text:sub(index))
  return table.concat(parts)
end

---Every string in this run that must not survive into a message: password file
---paths, vault id sources, the askpass helper, and the password itself.
---@param argv string[]
---@param creds table|nil
---@return string[]
local function sensitive_strings(argv, creds)
  local seen, values = {}, {}

  local function add(value)
    if type(value) ~= "string" or #value < 2 or seen[value] then
      return
    end
    seen[value] = true
    table.insert(values, value)
    local source = value:match("^[^@]+@(.+)$")
    if source then
      add(source)
    end
  end

  local pending = false
  for _, arg in ipairs(argv) do
    if pending then
      add(arg)
      pending = false
    else
      pending = CREDENTIAL_FLAGS[arg] == true
    end
  end

  for name, value in pairs((creds and creds.env) or {}) do
    if type(value) == "string" and value ~= "False" then
      if name == "ANSIBLE_VAULT_IDENTITY_LIST" then
        for entry in value:gmatch("[^,]+") do
          add(entry)
        end
      else
        add(value)
      end
    end
  end

  -- Longest first, so a full `label@source` is replaced before its source half
  -- turns the surrounding text into a partial match.
  table.sort(values, function(a, b)
    return #a > #b
  end)
  return values
end

---Describe a failed run without echoing anything the child was trusted with.
---@param action string
---@param exit_code integer
---@param stderr string
---@param argv string[]
---@param creds table|nil
---@return string
local function failure_message(action, exit_code, stderr, argv, creds)
  local summary = stderr
  for _, value in ipairs(sensitive_strings(argv, creds)) do
    summary = replace_plain(summary, value, "<redacted>")
  end

  summary = summary:gsub("%s+$", ""):gsub("^%s+", "")
  if #summary > MAX_MESSAGE then
    summary = summary:sub(1, MAX_MESSAGE) .. "..."
  end

  if summary == "" then
    return string.format("ansible-vault %s exited with status %d", action, exit_code)
  end
  return string.format("ansible-vault %s failed: %s", action, summary)
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
---@return vim.SystemObj|nil
local function spawn(action, args, opts, creds, stdin, file, callback)
  local argv = M.build_argv(action, args or {}, file or "-", opts)

  -- The subcommand's own environment is applied here rather than folded into the
  -- credentials, because it is a property of the subcommand: `rekey` inheriting
  -- an encrypt identity re-encrypts with the *old* password and still reports
  -- success, so this must not be something a caller can forget to ask for.
  local action_env = credentials.action_env(action)
  local env
  if (creds and creds.env) or action_env then
    env = vim.tbl_extend("force", (creds and creds.env) or {}, action_env or {})
  end

  local budget = timeout()

  -- Deliberately not `text = true`: that would normalize CRLF in the output,
  -- rewriting the line endings of whatever was decrypted.
  local ok, result = pcall(vim.system, argv, {
    cwd = creds and creds.cwd or nil,
    env = env,
    timeout = budget,
    stdin = stdin,
  }, function(completed)
    vim.schedule(function()
      if completed.code == 0 then
        callback(true, completed.stdout or "")
      elseif completed.code == 124 then
        callback(false, string.format("ansible-vault %s timed out after %dms", action, budget or 0))
      else
        callback(false, failure_message(action, completed.code, completed.stderr or "", argv, creds))
      end
    end)
  end)

  if not ok then
    -- The exception quotes the argv back, which carries vault ids and the
    -- askpass helper path, so it is dropped rather than summarised.
    callback(false, string.format("Failed to start %s", argv[1] or "ansible-vault"))
    return nil
  end

  return result
end

---Run `ansible-vault` over content piped on stdin.
---
---The returned handle is how a caller cancels a run whose result it no longer
---wants — a buffer closed mid-operation, or a save that has already been
---superseded. `callback` still fires for a killed process.
---@param action string The vault action (encrypt, decrypt, encrypt_string)
---@param input string Input content
---@param args string[] Additional arguments
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
---@param creds? AnsibleVaultCredentials Supplies the child cwd and environment
---@return vim.SystemObj|nil
function M.run(action, input, args, callback, opts, creds)
  return spawn(action, args, opts, creds, input, nil, callback)
end

---Run `ansible-vault` against a file path.
---
---The path is passed to the child as given, so it must be absolute: the child
---runs in the directory `ansible.cfg` was found in, not in Neovim's.
---@param action string
---@param file_path string
---@param args string[]
---@param callback fun(success: boolean, output: string): nil
---@param opts? table
---@param creds? AnsibleVaultCredentials
---@return vim.SystemObj|nil
function M.run_file(action, file_path, args, callback, opts, creds)
  return spawn(action, args, opts, creds, nil, file_path, callback)
end

return M
