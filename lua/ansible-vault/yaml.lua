---YAML and vault-header parsing.
---
---Ansible accepts far more shapes than a naive pattern suggests. All of these are
---valid inline vault values and are handled here:
---
---    key: !vault |            "key": !vault |          - key: !vault |
---    key: !vault |-           'key': !vault |          - !vault |
---
---plus arbitrary nesting and any ciphertext indentation. The rule that keeps this
---honest: never guess where the ciphertext starts, locate the `$ANSIBLE_VAULT`
---header line and read from there.
local M = {}

---Characters a bare YAML key may not start with, because they introduce
---comments, tags, anchors, aliases, or flow collections.
local BARE_KEY_REJECT_FIRST = "[#!&*%[%]{}|>%%@`,]"

---@class AnsibleVaultHeader
---@field version string Vault format version, for example "1.1" or "1.2"
---@field cipher string Cipher name, in practice always "AES256"
---@field label string|nil Vault ID label, only present in format 1.2 and newer

---Parse an `$ANSIBLE_VAULT;1.2;AES256;label` header line.
---Leading whitespace is tolerated so inline blocks parse the same as whole files.
---@param line string|nil
---@return AnsibleVaultHeader|nil
function M.parse_header(line)
  if type(line) ~= "string" then
    return nil
  end

  local body = line:match("^%s*%$ANSIBLE_VAULT;(.*)$")
  if not body then
    return nil
  end

  body = body:gsub("[\r%s]+$", "")
  local parts = vim.split(body, ";", { plain = true })
  local version, cipher, label = parts[1], parts[2], parts[3]

  if not version or not version:match("^%d[%d%.]*$") then
    return nil
  end
  if not cipher or not cipher:match("^%w+$") then
    return nil
  end
  if label == "" then
    label = nil
  end

  return { version = version, cipher = cipher, label = label }
end

---@param line string|nil
---@return boolean
function M.is_vault_header(line)
  return M.parse_header(line) ~= nil
end

---@param line string
---@return integer
function M.indent_width(line)
  return #(line:match("^([ \t]*)") or "")
end

---Drop a trailing `# comment`, respecting quotes.
---@param line string
---@return string
function M.strip_comment(line)
  local quote = nil
  local escaped = false

  for i = 1, #line do
    local char = line:sub(i, i)

    if quote then
      if quote == '"' and char == "\\" and not escaped then
        escaped = true
      else
        if char == quote and not escaped then
          quote = nil
        end
        escaped = false
      end
    elseif char == "'" or char == '"' then
      quote = char
    elseif char == "#" and (i == 1 or line:sub(i - 1, i - 1):match("%s")) then
      return line:sub(1, i - 1)
    end
  end

  return line
end

---@param value string
---@return string
function M.unquote(value)
  local quote = value:match("^(['\"])")
  if not quote then
    return value
  end

  local escaped = false
  for i = 2, #value do
    local char = value:sub(i, i)
    if quote == '"' and char == "\\" and not escaped then
      escaped = true
    else
      if char == quote and not escaped then
        local result = value:sub(2, i - 1)
        if quote == '"' then
          result = result:gsub('\\"', '"'):gsub("\\\\", "\\")
        end
        return result
      end
      escaped = false
    end
  end

  return value:sub(2)
end

---@class AnsibleVaultKeyLine
---@field indent string Whitespace before the (optional) list dash
---@field dash string The list item prefix, for example "- ", or ""
---@field key string The key with quotes removed
---@field key_raw string The key exactly as written
---@field rest string Everything after the colon and its trailing spaces
---@field value_col integer Byte offset in the original line where `rest` starts

---Split a `key: value` line, tolerating quoted keys and list-item prefixes.
---@param line string
---@return AnsibleVaultKeyLine|nil
function M.parse_key_line(line)
  if type(line) ~= "string" then
    return nil
  end

  local indent = line:match("^([ \t]*)") or ""
  local remainder = line:sub(#indent + 1)

  local dash = ""
  local dashed, after_dash = remainder:match("^(%-[ \t]+)(.*)$")
  if dashed then
    dash = dashed
    remainder = after_dash
  end

  local key_raw, rest = remainder:match('^("[^"]*")[ \t]*:[ \t]*(.*)$')
  if not key_raw then
    key_raw, rest = remainder:match("^('[^']*')[ \t]*:[ \t]*(.*)$")
  end
  if not key_raw then
    key_raw, rest = remainder:match("^([^%s][^:]*)[ \t]*:[ \t]*(.*)$")
    if key_raw and (key_raw:sub(1, 1):match(BARE_KEY_REJECT_FIRST) or key_raw:match("%s#")) then
      return nil
    end
  end

  if not key_raw or key_raw == "" then
    return nil
  end

  return {
    indent = indent,
    dash = dash,
    key = M.unquote(key_raw),
    key_raw = key_raw,
    rest = rest,
    value_col = #line - #rest,
  }
end

---Split a `key: value` line and resolve the scalar value.
---Returns nil for the value when it introduces a block scalar or is absent.
---@param line string
---@return string|nil indent
---@return string|nil key
---@return string|nil value
function M.extract_key_value(line)
  local parsed = M.parse_key_line(line)
  if not parsed then
    return nil, nil, nil
  end

  local rest = parsed.rest
  if rest == "" or rest:match("^!") then
    return parsed.indent, parsed.key, nil
  end

  rest = M.strip_comment(rest):gsub("%s+$", "")
  if rest == "" then
    return parsed.indent, parsed.key, ""
  end

  return parsed.indent, parsed.key, M.unquote(rest)
end

---Recognize the `!vault |`, `!vault |-`, `!vault |2+`, `!vault >` … introducers.
---@param rest string|nil
---@return table|nil
function M.parse_block_scalar(rest)
  if type(rest) ~= "string" then
    return nil
  end

  local after = rest:match("^!vault[ \t]*(.*)$")
  if not after then
    return nil
  end

  after = M.strip_comment(after):gsub("%s+$", "")
  local style, mods = after:match("^([|>])([%d%-%+]*)$")
  if not style then
    return nil
  end

  return { style = style, mods = mods }
end

---True when the line opens an inline vault block.
---@param line string
---@return boolean
function M.is_block_opener(line)
  local parsed = M.parse_key_line(line)
  if parsed and M.parse_block_scalar(parsed.rest) then
    return true
  end

  -- A bare `- !vault |` or `!vault |` with no key.
  local bare = line:match("^[ \t]*%-?[ \t]*(.*)$")
  return M.parse_block_scalar(bare) ~= nil
end

---Locate the inline vault block containing `cursor_row`.
---@param lines string[] All buffer lines
---@param cursor_row integer 1-based
---@return integer|nil start_row 1-based
---@return integer|nil end_row 1-based
function M.find_block(lines, cursor_row)
  local start_row

  for row = cursor_row, 1, -1 do
    local line = lines[row] or ""
    if M.is_block_opener(line) then
      start_row = row
      break
    end

    -- Stop at the first unindented non-blank line above the cursor; the block
    -- opener always sits at or below that level.
    if row ~= cursor_row and line:match("%S") and not line:match("^[ \t]") then
      break
    end
  end

  if not start_row then
    if M.is_vault_header(lines[cursor_row]) then
      start_row = cursor_row
    else
      return nil
    end
  end

  local base_indent = M.indent_width(lines[start_row] or "")
  local end_row = start_row

  for row = start_row + 1, #lines do
    local line = lines[row] or ""
    if line:match("%S") then
      if M.indent_width(line) <= base_indent then
        break
      end
      end_row = row
    end
  end

  if cursor_row > end_row then
    return nil
  end

  return start_row, end_row
end

---@class AnsibleVaultBlock
---@field vault_content string Dedented ciphertext, ready for `ansible-vault decrypt`
---@field var_name string|nil YAML key the block belongs to
---@field indent string Indentation of the key line
---@field dash string List item prefix of the key line
---@field header AnsibleVaultHeader|nil Parsed vault header

---Parse an inline vault block into its ciphertext and surrounding YAML shape.
---@param content string The block text, starting at the key or ciphertext line
---@return AnsibleVaultBlock|nil
function M.parse_block(content)
  if type(content) ~= "string" then
    return nil
  end

  local lines = vim.split(content, "\n", { plain = true })
  for i, line in ipairs(lines) do
    lines[i] = line:gsub("\r$", "")
  end

  local var_name, indent, dash = nil, "", ""
  local first = lines[1] or ""

  local key_line = M.parse_key_line(first)
  if key_line and M.parse_block_scalar(key_line.rest) then
    var_name = key_line.key
    indent = key_line.indent
    dash = key_line.dash
  else
    local bare_indent, bare = first:match("^([ \t]*)(.*)$")
    local bare_dash, after = bare:match("^(%-[ \t]+)(.*)$")
    if bare_dash and M.parse_block_scalar(after) then
      indent = bare_indent
      dash = bare_dash
    elseif M.parse_block_scalar(bare) then
      indent = bare_indent
    end
  end

  -- Never guess: find the line that actually carries the vault header.
  local first_cipher
  for i, line in ipairs(lines) do
    if M.is_vault_header(line) then
      first_cipher = i
      break
    end
  end

  if not first_cipher then
    return nil
  end

  local cipher_lines = {}
  for i = first_cipher, #lines do
    if lines[i]:match("%S") then
      table.insert(cipher_lines, lines[i])
    end
  end

  if #cipher_lines == 0 then
    return nil
  end

  local min_indent = math.huge
  for _, line in ipairs(cipher_lines) do
    min_indent = math.min(min_indent, M.indent_width(line))
  end

  if min_indent < math.huge and min_indent > 0 then
    for i, line in ipairs(cipher_lines) do
      cipher_lines[i] = line:sub(min_indent + 1)
    end
  end

  return {
    vault_content = table.concat(cipher_lines, "\n"),
    var_name = var_name,
    indent = indent,
    dash = dash,
    header = M.parse_header(cipher_lines[1]),
  }
end

local BOOLEAN_WORDS = {
  yes = true,
  no = true,
  ["true"] = true,
  ["false"] = true,
  null = true,
  on = true,
  off = true,
  y = true,
  n = true,
  Y = true,
  N = true,
  YES = true,
  NO = true,
  TRUE = true,
  FALSE = true,
  NULL = true,
  ON = true,
  OFF = true,
}

---@param value string
---@return boolean
function M.needs_quoting(value)
  if value == "" then
    return true
  end
  if value:sub(1, 1):match("[%[%{%]%}'\"&*!|>%%@`~]") then
    return true
  end
  if value:match("#") or value:match(": ") or value:match("%s$") or value:match("^%s") then
    return true
  end
  if BOOLEAN_WORDS[value] then
    return true
  end
  return false
end

---@param value string
---@return string
function M.quote_value(value)
  if not M.needs_quoting(value) then
    return value
  end
  local escaped = value:gsub("\\", "\\\\"):gsub('"', '\\"')
  return '"' .. escaped .. '"'
end

return M
