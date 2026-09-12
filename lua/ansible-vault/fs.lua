---Filesystem writes that cannot leave a half-written vault behind.
---
---Encrypted output replaces the only copy of a file's ciphertext, so a partial
---write is data loss rather than an inconvenience. Every write goes to a sibling
---temporary file, is `fsync`ed, and only then renamed into place, which is the
---sequence a crash cannot interrupt into a truncated file.
---
---Nothing here touches a buffer, so it is safe to call from any code path.
local M = {}

local uv = vim.uv

local DEFAULT_MODE = 384 -- 0600

---Write `data` to `path` atomically, inheriting the existing file's mode.
---
---A new file is created `0600`: the content is a secret, and widening that is
---the user's decision to make, not a default to inherit from the umask.
---@param path string
---@param data string
---@return boolean ok
---@return string|nil err
function M.atomic_write(path, data)
  local dir = vim.fn.fnamemodify(path, ":h")
  local tail = vim.fn.fnamemodify(path, ":t")
  local bytes = uv.random(4)
  local nonce = bytes:byte(1) * 16777216 + bytes:byte(2) * 65536 + bytes:byte(3) * 256 + bytes:byte(4)
  local tmp = string.format("%s/.%s.ansible-vault.nvim.%d.%d", dir, tail, uv.getpid(), nonce)

  local mode = DEFAULT_MODE
  local stat = uv.fs_stat(path)
  if stat and stat.mode then
    mode = stat.mode % 512
  end

  local fd, open_err = uv.fs_open(tmp, "wx", mode)
  if not fd then
    return false, open_err or "failed to create temporary output file"
  end

  local written, write_err = uv.fs_write(fd, data)
  if type(written) == "number" and written >= #data then
    -- Durability matters here: the rename replaces the only copy of the
    -- ciphertext, so the new contents have to be on disk before it happens.
    uv.fs_fsync(fd)
  end
  uv.fs_close(fd)

  if type(written) ~= "number" or written < #data then
    os.remove(tmp)
    return false, write_err or "failed to write encrypted output"
  end

  local ok, rename_err = uv.fs_rename(tmp, path)
  if not ok then
    os.remove(tmp)
    return false, rename_err or "failed to replace original file"
  end

  local dir_fd = uv.fs_open(dir, "r", DEFAULT_MODE)
  if dir_fd then
    pcall(uv.fs_fsync, dir_fd)
    uv.fs_close(dir_fd)
  end

  return true, nil
end

---Read a whole file as bytes.
---
---Used for the ciphertext staging file `:VaultRekey` runs the native rekey on, so
---nothing here decodes or normalises anything: the bytes are the file.
---@param path string
---@return string|nil data
---@return string|nil err
function M.read_file(path)
  local fd, open_err = uv.fs_open(path, "r", DEFAULT_MODE)
  if not fd then
    return nil, open_err or "failed to open file"
  end

  local chunks = {}
  local offset = 0
  while true do
    local chunk, read_err = uv.fs_read(fd, 65536, offset)
    if chunk == nil then
      uv.fs_close(fd)
      return nil, read_err or "failed to read file"
    end
    if chunk == "" then
      break
    end
    chunks[#chunks + 1] = chunk
    offset = offset + #chunk
  end
  uv.fs_close(fd)

  return table.concat(chunks), nil
end

---Delete a file, ignoring a missing one.
---@param path string
function M.remove(path)
  pcall(uv.fs_unlink, path)
end

---Snapshot what a file looks like on disk, for detecting outside changes.
---
---Size and timestamps rather than a hash: the point is to notice that someone
---else wrote the file while a scratch buffer was open, and reading the whole
---ciphertext again to compare would be slower for no extra certainty.
---@param path string
---@return table|nil
function M.signature(path)
  local stat = uv.fs_stat(path)
  if not stat then
    return nil
  end

  return {
    size = stat.size,
    mtime_sec = stat.mtime and stat.mtime.sec or 0,
    mtime_nsec = stat.mtime and stat.mtime.nsec or 0,
    ctime_sec = stat.ctime and stat.ctime.sec or 0,
    ctime_nsec = stat.ctime and stat.ctime.nsec or 0,
  }
end

---@param left table|nil
---@param right table|nil
---@return boolean
function M.same_signature(left, right)
  if not left or not right then
    return left == right
  end

  return left.size == right.size
    and left.mtime_sec == right.mtime_sec
    and left.mtime_nsec == right.mtime_nsec
    and left.ctime_sec == right.ctime_sec
    and left.ctime_nsec == right.ctime_nsec
end

return M
