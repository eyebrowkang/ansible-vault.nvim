---Small utilities shared by the quick and real suites; no plugin or fake setup.
local S = {}

function S.assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error(
      (message or "values differ") .. "\nexpected: " .. vim.inspect(expected) .. "\nactual: " .. vim.inspect(actual),
      2
    )
  end
end

function S.assert_true(value, message)
  if not value then
    error(message or "expected truthy value", 2)
  end
end

function S.assert_false(value, message)
  S.assert_true(not value, message or "expected false value")
end

function S.write_file(path, contents)
  local file = assert(io.open(path, "wb"))
  assert(file:write(contents))
  assert(file:close())
end

function S.read_file(path)
  local file = assert(io.open(path, "rb"))
  local contents = file:read("*a")
  assert(file:close())
  return contents
end

---Uses Neovim's process-owned temporary tree, removed when that process exits.
---Suites still own buffer teardown and environment/option restoration.
function S.temp_dir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

function S.lines(buf)
  return vim.api.nvim_buf_get_lines(buf or 0, 0, -1, false)
end

function S.open_file(path)
  vim.cmd("silent edit " .. vim.fn.fnameescape(path))
  return vim.api.nvim_get_current_buf()
end

---Open a file by its short name, retaining Neovim's distinct short/full names.
---Tests use this to cover BufWriteCmd's relative `event.file` behavior.
function S.open_file_relative(dir, name)
  vim.cmd("cd " .. vim.fn.fnameescape(dir))
  vim.cmd("silent edit " .. vim.fn.fnameescape(name))
  local buf = vim.api.nvim_get_current_buf()
  local short = vim.fn.bufname(buf)
  local full = vim.api.nvim_buf_get_name(buf)
  if short == full or full ~= dir .. "/" .. name then
    error("relative open did not retain distinct buffer names: " .. vim.inspect({ short = short, full = full }), 2)
  end
  return buf, full
end

return S
