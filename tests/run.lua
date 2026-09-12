vim.opt.runtimepath:prepend(vim.fn.getcwd())

-- `dofile` rather than `require`: only `lua/` is on the runtimepath, and adding
-- `tests/` to it just to load the specs would put them on users' paths too.
local root = vim.fn.getcwd() .. "/tests/"
local H = dofile(root .. "helpers.lua")

local tests = {}
for _, spec in ipairs({ "spec_core", "spec_privacy", "spec_credentials", "spec_async" }) do
  dofile(root .. spec .. ".lua")(H, tests)
end

-- Sorted, not `pairs()`. Random order meant a test could pass or fail depending
-- on what ran before it, which is how an order-dependent flake hides.
local names = vim.tbl_keys(tests)
table.sort(names)

local filter = vim.env.TEST_FILTER
local failures, ran = 0, 0
for _, name in ipairs(names) do
  if not filter or name:find(filter, 1, true) then
    ran = ran + 1
    io.stdout:write("TEST ", name, "\n")
    local ok, err = H.run(tests[name])
    if not ok then
      failures = failures + 1
      io.stderr:write("FAILED ", name, "\n", err, "\n")
    end
  end
end

if failures > 0 then
  vim.cmd("cquit")
end

if filter and ran == 0 then
  io.stderr:write("no test matched TEST_FILTER=", filter, "\n")
  vim.cmd("cquit")
end

io.stdout:write(string.format("All tests passed (%d)\n", ran))
io.stdout:flush()
vim.cmd("qa!")
