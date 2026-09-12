---Single YAML scalars and vault envelopes.
---
---Deliberately not a YAML document parser. It knows exactly two shapes and
---rejects everything else *before* Ansible is invoked, because a wrong guess here
---silently encrypts or destroys data the user never selected:
---
---  * one scalar — `key: value`, `- key: value`, `- value`, or a literal `|`
---    block with its indented body;
---  * one vault envelope — `key: !vault |` plus an evenly indented
---    `$ANSIBLE_VAULT` header and hex payload.
---
---The pair `parse_plaintext` / `format_plaintext` is the whole reason an inline
---value survives a decrypt/encrypt round trip byte for byte. A decrypted value is
---arbitrary bytes: it can be empty, start with a space, contain newlines, or end
---with none, one or several of them. Rendering it as a literal block with an
---explicit indentation indicator and an explicit chomping indicator is what makes
---all of those readable in the buffer *and* recoverable exactly.
local M = {}

local BARE_KEY_REJECT_FIRST = "[#!&*%[%]{}|>%%@`,]"

function M.parse_header(line)
  if type(line) ~= "string" then
    return nil
  end
  local body = line:match("^%s*%$ANSIBLE_VAULT;(.-)%s*$")
  if not body then
    return nil
  end
  local parts = vim.split(body, ";", { plain = true })
  if (#parts ~= 3 and #parts ~= 2) or not parts[1]:match("^%d[%d%.]*$") or not parts[2]:match("^%w+$") then
    return nil
  end
  return { version = parts[1], cipher = parts[2], label = parts[3] ~= "" and parts[3] or nil }
end

function M.is_vault_header(line)
  return M.parse_header(line) ~= nil
end

function M.indent_width(line)
  return #(line:match("^([ \t]*)") or "")
end

function M.strip_comment(line)
  local quote, escaped
  local i = 1
  while i <= #line do
    local c = line:sub(i, i)
    if quote then
      if quote == '"' and c == "\\" and not escaped then
        escaped = true
      else
        if c == quote and not escaped then
          if quote == "'" and line:sub(i + 1, i + 1) == "'" then
            i = i + 1
          else
            quote = nil
          end
        end
        escaped = false
      end
    elseif c == "'" or c == '"' then
      quote = c
    elseif c == "#" and (i == 1 or line:sub(i - 1, i - 1):match("%s")) then
      return line:sub(1, i - 1)
    end
    i = i + 1
  end
  return line
end

local ESCAPES = {
  ["0"] = "\0",
  a = "\7",
  b = "\8",
  t = "\t",
  n = "\n",
  v = "\11",
  f = "\12",
  r = "\r",
  e = "\27",
  [" "] = " ",
  ['"'] = '"',
  ["/"] = "/",
  ["\\"] = "\\",
  N = "\194\133",
  _ = "\194\160",
  L = "\226\128\168",
  P = "\226\128\169",
}

local function scalar(value)
  value = M.strip_comment(value):gsub("[ \t]+$", "")
  local quote = value:sub(1, 1)
  if quote ~= "'" and quote ~= '"' then
    if value:match("^[!&*%[%]{}|>@`%%]") or value:match(":%s") or value:match("^%-[ \t]") then
      return nil, "select one scalar, not a YAML collection, tag, or alias"
    end
    return value
  end
  local out, i = {}, 2
  while i <= #value do
    local c = value:sub(i, i)
    if c == quote then
      if quote == "'" and value:sub(i + 1, i + 1) == "'" then
        out[#out + 1] = "'"
        i = i + 2
      elseif i == #value then
        return table.concat(out)
      else
        return nil, "unexpected text after quoted scalar"
      end
    elseif quote == '"' and c == "\\" then
      local escape = value:sub(i + 1, i + 1)
      local width = ({ x = 2, u = 4, U = 8 })[escape]
      if width then
        local hex = value:sub(i + 2, i + 1 + width)
        local code = #hex == width and hex:match("^%x+$") and tonumber(hex, 16) or nil
        if not code or code > 0x10ffff or (code >= 0xd800 and code <= 0xdfff) then
          return nil, "invalid Unicode escape"
        end
        out[#out + 1] = vim.fn.nr2char(code)
        i = i + width + 2
      elseif ESCAPES[escape] then
        out[#out + 1] = ESCAPES[escape]
        i = i + 2
      else
        return nil, "invalid quoted scalar escape"
      end
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return nil, "unterminated quoted scalar"
end

function M.unquote(value)
  return scalar(value)
end

---Keep the raw key and list prefix, not Ansible's re-rendering of the key.
function M.parse_key_line(line)
  if type(line) ~= "string" then
    return nil
  end
  local indent = line:match("^([ \t]*)") or ""
  local remainder = line:sub(#indent + 1)
  local dash, after = remainder:match("^(%-[ \t]+)(.*)$")
  dash = dash or ""
  remainder = after or remainder
  local quote, escaped, colon
  local i = 1
  while i <= #remainder do
    local c = remainder:sub(i, i)
    if quote then
      if quote == '"' and c == "\\" and not escaped then
        escaped = true
      else
        if c == quote and not escaped then
          if quote == "'" and remainder:sub(i + 1, i + 1) == "'" then
            i = i + 1
          else
            quote = nil
          end
        end
        escaped = false
      end
    elseif i == 1 and (c == "'" or c == '"') then
      quote = c
    elseif c == ":" and (i == #remainder or remainder:sub(i + 1, i + 1):match("[ \t]")) then
      colon = i
      break
    end
    i = i + 1
  end
  if not colon then
    return nil
  end
  local raw = remainder:sub(1, colon - 1):gsub("[ \t]+$", "")
  if raw == "" or raw:sub(1, 1):match(BARE_KEY_REJECT_FIRST) or raw:match("%s#") then
    return nil
  end
  local key = scalar(raw)
  if not key then
    return nil
  end
  local rest = remainder:sub(colon + 1):gsub("^[ \t]*", "")
  return { indent = indent, dash = dash, key = key, key_raw = raw, rest = rest, value_col = #line - #rest }
end

local function literal(rest, tagged)
  if tagged then
    rest = rest:match("^!vault[ \t]+(.*)$")
    if not rest then
      return nil
    end
  end
  rest = M.strip_comment(rest):gsub("%s+$", "")
  local style, mods = rest:match("^([|>])([1-9%+%-]*)$")
  if not style or #mods > 2 then
    return nil
  end
  local digit = mods:match("[1-9]")
  local chomp = mods:match("[%+%-]")
  if #mods ~= (digit and 1 or 0) + (chomp and 1 or 0) then
    return nil
  end
  return { style = style, mods = mods, indent = tonumber(digit), chomp = chomp }
end

function M.parse_block_scalar(rest)
  return type(rest) == "string" and literal(rest, true) or nil
end

local function shape(line)
  local key = M.parse_key_line(line)
  if key then
    key.var_name = key.key
    return key
  end
  local indent, rest = line:match("^([ \t]*)(.*)$")
  local dash, after = rest:match("^(%-[ \t]+)(.*)$")
  return { indent = indent, dash = dash or "", rest = after or rest }
end

function M.is_block_opener(line)
  return type(line) == "string" and M.parse_block_scalar(shape(line).rest) ~= nil
end

---Validate a complete vault envelope, returning its lines without the trailing
---blank one.
---
---Used before a child process's output is allowed to replace data on disk or in a
---buffer: `ansible-vault` exiting 0 is not by itself proof that it produced
---ciphertext. A header line alone is not an envelope, and every payload line must
---be an even-length run of hex digits.
---@param content string
---@return string[]|nil
function M.vault_lines(content)
  local lines = vim.split(content, "\n", { plain = true })
  if lines[#lines] == "" then
    table.remove(lines)
  end
  for i, line in ipairs(lines) do
    lines[i] = line:gsub("\r$", "")
  end
  if #lines < 2 or not M.parse_header(lines[1]) then
    return nil
  end
  for i = 2, #lines do
    if not lines[i]:match("^%x+$") or #lines[i] % 2 ~= 0 then
      return nil
    end
  end
  return lines
end

---Parse one `key: !vault |` block, keeping the key exactly as it was written.
---@param content string
---@return table|nil parsed `indent`, `dash`, `key_raw`, `var_name`, `vault_content`, `header`
function M.parse_block(content)
  if type(content) ~= "string" then
    return nil
  end
  local lines = vim.split(content, "\n", { plain = true })
  if lines[#lines] == "" then
    table.remove(lines)
  end
  for i, line in ipairs(lines) do
    lines[i] = line:gsub("\r$", "")
  end
  local parsed = shape(lines[1] or "")
  if not M.parse_block_scalar(parsed.rest) or #lines < 3 then
    return nil
  end
  local base = #parsed.indent + #parsed.dash
  local width = M.indent_width(lines[2])
  if width <= base or not M.is_vault_header(lines[2]) then
    return nil
  end
  local cipher = {}
  for i = 2, #lines do
    if M.indent_width(lines[i]) ~= width then
      return nil
    end
    cipher[#cipher + 1] = lines[i]:sub(width + 1)
  end
  if not M.vault_lines(table.concat(cipher, "\n")) then
    return nil
  end
  parsed.vault_content = table.concat(cipher, "\n") .. "\n"
  parsed.header = M.parse_header(cipher[1])
  return parsed
end

---Locate the single `!vault` block containing `cursor_row`, if there is one.
---
---Scans upwards for the nearest block opener and then forwards over the evenly
---indented payload. A cursor past the end of that payload is not "in" the block,
---so an unrelated line below one does not resolve to it.
---@param lines string[]
---@param cursor_row integer 1-based
---@return integer|nil start_row, integer|nil end_row both 1-based, inclusive
function M.find_block(lines, cursor_row)
  for start = cursor_row, 1, -1 do
    if M.is_block_opener(lines[start]) then
      local width = M.indent_width(lines[start + 1] or "")
      local last = start + 1
      if not M.is_vault_header(lines[last]) then
        return nil
      end
      while
        lines[last + 1]
        and M.indent_width(lines[last + 1]) == width
        and lines[last + 1]:sub(width + 1):match("^%x+$")
      do
        last = last + 1
      end
      if cursor_row > last then
        return nil
      end
      local block = {}
      for i = start, last do
        block[#block + 1] = lines[i]
      end
      if M.parse_block(table.concat(block, "\n")) then
        return start, last
      end
      return nil
    end
  end
end

---Recover the exact bytes a selected scalar stands for.
---
---The inverse of `format_plaintext`, and the only place that knows how a literal
---block's indentation indicator and chomping indicator map back onto trailing
---newlines. Anything it cannot read unambiguously is an error rather than a
---guess, so a selection that grabbed a neighbouring line is refused before
---`ansible-vault` ever runs.
---
---`last_eol` says whether a newline follows the final selected line in the
---buffer; without it a value ending in a newline could not be told apart from one
---that does not at the end of a file.
---@param lines string[]
---@param last_eol boolean
---@return table|nil parsed, string|nil err
function M.parse_plaintext(lines, last_eol)
  if #lines == 0 then
    return nil, "empty selection"
  end
  local parsed = shape(lines[1])
  if parsed.indent:find("\t") or parsed.dash:find("\t") then
    return nil, "tabs in YAML indentation are not supported"
  end
  local block = literal(parsed.rest, false)
  if not block then
    if #lines ~= 1 then
      return nil, "select exactly one scalar, including its literal block body"
    end
    local value, err = scalar(parsed.rest)
    if value == nil then
      return nil, err
    end
    parsed.content = value
    -- Anything below this line indented past the key belongs to this value:
    -- a nested mapping, a list, or a plain scalar continued on the next line.
    -- `vars:` with children under it is *not* an empty value to encrypt.
    parsed.continues_at = #parsed.indent + #parsed.dash + 1
    return parsed
  end
  if block.style ~= "|" then
    return nil, "folded YAML scalars are ambiguous; use a literal | scalar"
  end
  local base = #parsed.indent + #parsed.dash
  local width = block.indent and base + block.indent or nil
  if not width then
    for i = 2, #lines do
      if lines[i]:match("%S") then
        width = M.indent_width(lines[i])
        break
      end
    end
    width = width or base + 2
  end
  if width <= base then
    return nil, "literal body must be indented under its value"
  end
  local body = {}
  for i = 2, #lines do
    local line = lines[i]
    if line:match("%S") and (M.indent_width(line) < width or line:sub(1, width):find("\t")) then
      return nil, "selection includes text outside the literal scalar"
    end
    body[#body + 1] = #line >= width and line:sub(width + 1) or ""
  end
  local value = table.concat(body, "\n") .. (#body > 0 and last_eol and "\n" or "")
  if block.chomp == "-" then
    value = value:gsub("\n+$", "")
  elseif block.chomp ~= "+" then
    local had_eol = value:sub(-1) == "\n"
    value = value:gsub("\n+$", "")
    if value ~= "" and had_eol then
      value = value .. "\n"
    end
  end
  parsed.content = value
  -- A line below the selection indented this far is more of the same literal
  -- block, which means the selection cut the value in half.
  parsed.continues_at = width
  return parsed
end

function M.needs_quoting(value)
  return value == ""
    or value:find("[%c]") ~= nil
    or value:match("^[%s%d%[%{%]%}'\"&*!|>%%@`~%+%-%.]") ~= nil
    or value:match("[#:]%s?") ~= nil
    or value:match("%s$") ~= nil
    or ({
        yes = true,
        no = true,
        ["true"] = true,
        ["false"] = true,
        null = true,
        on = true,
        off = true,
        y = true,
        n = true,
      })[value:lower()]
      == true
end

function M.quote_value(value)
  return M.needs_quoting(value) and vim.json.encode(value) or value
end

local function prefix(parsed)
  return (parsed.indent or "") .. (parsed.dash or "") .. (parsed.key_raw and parsed.key_raw .. ": " or "")
end

---Render arbitrary bytes as the value of `parsed`'s key.
---
---A single line becomes a quoted scalar; anything with a newline becomes a
---literal block with an explicit `2` indentation indicator, so a value whose
---first line starts with a space is still unambiguous. The chomping indicator
---carries the trailing newline: `+` keeps every one of them, `-` says there was
---none. Bytes that no literal block can hold (carriage returns, control
---characters) fall back to a quoted scalar.
---@param value string
---@param parsed table From `parse_plaintext` or `parse_block`
---@param last_eol boolean Whether a newline will follow the last emitted line
---@return string[]
function M.format_plaintext(value, parsed, last_eol)
  if not value:find("\n", 1, true) or value:find("\r", 1, true) or value:find("[%z\1-\8\11\12\14-\31]") then
    return { prefix(parsed) .. M.quote_value(value) }
  end
  local trailing = value:sub(-1) == "\n"
  local body = vim.split(value, "\n", { plain = true })
  if trailing then
    table.remove(body)
  end
  local lines = { prefix(parsed) .. (trailing and "|2+" or "|2-") }
  local indent = (parsed.indent or "") .. string.rep(" ", #(parsed.dash or "") + 2)
  for _, line in ipairs(body) do
    lines[#lines + 1] = indent .. line
  end
  if trailing and not last_eol then
    lines[#lines + 1] = indent
  end
  return lines
end

---Pull the envelope out of `ansible-vault encrypt_string` output.
---
---Only the ciphertext is taken from the child. The key it echoes back is its own
---re-rendering of `--stdin-name`, which is not always the YAML the user wrote, so
---this locates the `$ANSIBLE_VAULT` header and reads the evenly indented payload
---from there rather than trying to parse that first line.
---@param output string
---@return string[]|nil
function M.extract_envelope(output)
  if type(output) ~= "string" then
    return nil
  end
  local lines = vim.split(output, "\n", { plain = true })
  for i, line in ipairs(lines) do
    lines[i] = line:gsub("\r$", "")
  end

  local first
  for i, line in ipairs(lines) do
    if M.is_vault_header(line) then
      first = i
      break
    end
  end
  if not first then
    return nil
  end

  local width = M.indent_width(lines[first])
  local envelope = {}
  for i = first, #lines do
    if lines[i] == "" then
      break
    end
    if M.indent_width(lines[i]) ~= width then
      return nil
    end
    envelope[#envelope + 1] = lines[i]:sub(width + 1)
  end

  return M.vault_lines(table.concat(envelope, "\n"))
end

---Render an encrypted scalar under `parsed`'s original key, indentation and list
---dash. The prefix comes from the buffer, never from the child's output.
---@param output string
---@param parsed table
---@return string[]|nil lines, string|nil err
function M.format_vault(output, parsed)
  local envelope = M.extract_envelope(output)
  if not envelope then
    return nil, "ansible-vault returned an invalid encrypted scalar"
  end
  local lines = { prefix(parsed) .. "!vault |" }
  local indent = (parsed.indent or "") .. string.rep(" ", #(parsed.dash or "") + 2)
  for _, line in ipairs(envelope) do
    lines[#lines + 1] = indent .. line
  end
  return lines
end

return M
