# ansible-vault.nvim

> **警告**：这个插件仍处于早期开发阶段。加密、解密操作前请先备份重要文件。

`ansible-vault.nvim` 是一个 Neovim 插件，用来在编辑器里更方便地处理
Ansible Vault 文件和 YAML inline vault 字符串。

English documentation: [README.md](README.md)

## 功能

- 加密/解密当前 buffer
- 在只读浮窗中查看加密内容
- 将选中文本加密为 YAML inline vault 字符串
- 在光标下加密、查看、解密 inline vault 字符串
- 在加密/解密状态之间切换
- 对加密文件执行 rekey
- 将当前 buffer 解密后与另一个文件或 Git 版本做 diff
- 使用 Telescope 或内置 `vim.ui.select` 查找 vault 文件
- 自动识别 Ansible Vault 文件
- 可选：打开加密文件时自动进入 `VaultEdit` 安全编辑流程
- 支持 password file、一个或多个 vault ID 和交互式密码输入
- 可选：在内存中短时缓存交互式密码
- 支持命令级凭据覆盖和命令行补全
- `:VaultInfo` 查看当前 buffer 和插件配置诊断信息
- 可配置 vault 命令超时和成功通知静音
- 通过 `User` autocmd events 集成 statusline 或其他插件
- 支持 `:checkhealth ansible-vault` 诊断
- 支持通过 `conda run` 调用 Conda 环境中的 `ansible-vault`
- 可用于 statusline 显示 vault 状态

## 依赖

- Neovim >= 0.9.0
- `ansible-vault` 可执行文件在 `PATH` 中，或通过配置指定路径/Conda 环境

## 安装

### lazy.nvim

```lua
{
  "eyebrowkang/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup({
      password_file = "~/.ansible/vault-pass",
    })
  end,
}
```

### packer.nvim

```lua
use {
  "eyebrowkang/ansible-vault.nvim",
  config = function()
    require("ansible-vault").setup()
  end,
}
```

## 配置

```lua
require("ansible-vault").setup({
  -- ansible-vault password file 路径
  password_file = nil,

  -- vault ID，例如 "prod@~/.ansible/prod-pass"
  vault_id = nil,

  -- 多个 vault ID。设置后优先于 vault_id。
  vault_ids = nil,

  -- 加密时使用的 vault ID label。
  -- 保持 nil 时，由 ansible-vault 根据已配置的 vault IDs 自行选择。
  encrypt_vault_id = nil,

  -- :VaultRekey 使用的新 password file
  rekey_password_file = nil,

  -- :VaultRekey 使用的新 vault ID，例如 "prod@~/.ansible/new-pass"
  rekey_vault_id = nil,

  -- 读取文件后自动识别 Ansible Vault 文件
  auto_detect = true,

  -- 读取加密文件后自动使用 :VaultEdit 打开安全编辑 buffer
  auto_edit = false,

  -- 交互式密码在内存中的缓存秒数。0 表示每次操作都重新询问。
  password_cache_ttl = 0,

  -- :VaultFiles picker 后端："auto"、"telescope" 或 "builtin"
  picker = "auto",

  -- ansible-vault 命令超时时间，单位毫秒。0 表示关闭超时。
  timeout_ms = 30000,

  -- 操作成功后是否显示 info 级通知
  notify_success = true,

  -- ansible-vault 所在的 Conda 环境名
  -- 插件会执行：conda run -n <env> ansible-vault ...
  conda_env = nil,

  -- 自定义 ansible-vault 可执行文件路径
  ansible_vault_path = nil,

  -- 开启调试日志
  debug = false,
})
```

### 密码来源

插件按以下顺序选择凭据：

1. `password_file`
2. `vault_ids`
3. `vault_id`
4. 交互式密码输入

单密码文件场景：

```lua
require("ansible-vault").setup({
  password_file = "~/.ansible/vault-pass",
})
```

多 vault ID 场景：

```lua
require("ansible-vault").setup({
  vault_id = "prod@~/.ansible/prod-pass",
  encrypt_vault_id = "prod",
})
```

需要多个 vault identity 时：

```lua
require("ansible-vault").setup({
  vault_ids = {
    "dev@~/.ansible/dev-pass",
    "prod@~/.ansible/prod-pass",
  },
  encrypt_vault_id = "prod",
})
```

如果不希望插件显式传入 `--encrypt-vault-id`，保持
`encrypt_vault_id = nil`。

大多数命令也支持临时覆盖凭据配置。覆盖只对本次命令生效，不会修改全局
`setup()` 配置：

```vim
:VaultEdit --vault-id prod@~/.ansible/prod-pass
:VaultView --vault-password-file ~/.ansible/prod-pass
:VaultEncryptString prod
```

像 `prod` 这样的裸 label 快捷写法只用于 inline 加密命令，等价于
`--encrypt-vault-id prod`。

为 `VaultRekey` 配置新密码文件或新 vault ID：

```lua
require("ansible-vault").setup({
  password_file = "~/.ansible/old-pass",
  rekey_password_file = "~/.ansible/new-pass",
})
```

```lua
require("ansible-vault").setup({
  vault_id = "old@~/.ansible/old-pass",
  rekey_vault_id = "new@~/.ansible/new-pass",
})
```

如果 `ansible-vault` 不在 `PATH` 中：

```lua
require("ansible-vault").setup({
  ansible_vault_path = "/opt/homebrew/bin/ansible-vault",
  password_file = "~/.ansible/vault-pass",
})
```

如果 `ansible-vault` 安装在 Conda 环境中：

```lua
require("ansible-vault").setup({
  conda_env = "ansible-dev",
  password_file = "~/.ansible/vault-pass",
})
```

如果你主要使用交互式密码，可以短时间缓存在 Neovim 进程内存中：

```lua
require("ansible-vault").setup({
  password_cache_ttl = 300,
})
```

密码缓存默认关闭。需要手动清理时执行 `:VaultClearPasswordCache`。

## 命令

| 命令 | 说明 |
|------|------|
| `:VaultEncrypt` | 加密当前 buffer |
| `:VaultDecrypt` | 解密当前 buffer |
| `:VaultView` | 在只读浮窗中查看解密内容 |
| `:VaultEdit` | 在 scratch buffer 中编辑解密内容，`:write` 时重新加密保存 |
| `:VaultClearPasswordCache` | 清理内存中的交互式密码缓存 |
| `:VaultDiff {file}` | 将当前 buffer 解密后与另一个文件做 diff |
| `:VaultDiff --git [ref]` | 将当前文件解密后与某个 Git 版本做 diff |
| `:VaultFiles [view\|edit\|rekey]` | 选择 vault 文件并查看、编辑或 rekey |
| `:VaultInfo [args]` | 查看当前 buffer 和插件配置诊断信息 |
| `:VaultRekey [args]` | 对当前加密文件执行 rekey |
| `:VaultToggle` | 在加密/解密状态之间切换 |
| `:VaultEncryptString` | 加密视觉选择的文本 |
| `:VaultDecryptString` | 原地解密选中的 inline vault 字符串 |
| `:VaultViewString` | 查看视觉选择中的 inline vault 字符串 |
| `:VaultEncryptStringUnderCursor` | 加密光标所在 YAML value |
| `:VaultViewStringUnderCursor` | 查看光标所在 inline vault block |
| `:VaultDecryptStringUnderCursor` | 原地解密光标所在 inline vault block |

## 健康检查

执行：

```vim
:checkhealth ansible-vault
```

健康检查会验证 `ansible-vault` 可执行文件、password file 可读性和权限、
vault ID label、`encrypt_vault_id` 以及 `VaultRekey` 目标配置。

## 使用方式

### 加密普通文件

1. 打开普通 YAML 或文本文件。
2. 执行 `:VaultEncrypt`。
3. 确认结果后执行 `:write` 保存。

`:VaultEncrypt` 会把当前 buffer 内容替换为 Ansible Vault 密文，但不会自动
写入磁盘，这样你可以在保存前先检查结果。

### 原地解密加密文件

1. 打开以 `$ANSIBLE_VAULT` 开头的文件。
2. 执行 `:VaultDecrypt`。
3. 编辑解密后的内容。
4. 如果文件需要继续保持加密状态，保存前再次执行 `:VaultEncrypt`。

这个流程很直接，但明文会出现在原始 buffer 中。更安全的编辑方式是
`:VaultEdit`。

### 只读查看加密文件

在加密 buffer 中执行 `:VaultView`。插件会把解密内容放到只读浮窗中。
按 `q` 或 `<Esc>` 关闭浮窗。

### 安全编辑加密文件

在文件型加密 buffer 中执行 `:VaultEdit`。

插件会打开一个 scratch buffer 显示解密内容，并关闭 swapfile 和持久 undo。
在这个 scratch buffer 中执行 `:write` 时，插件会重新加密内容并写回原文件，
然后关闭 scratch buffer 并重新载入原始加密文件。

如果 scratch buffer 打开期间原文件在磁盘上发生了变化，插件会拒绝保存，
避免覆盖外部修改。

### 自动安全编辑加密文件

如果希望打开加密文件时直接进入更安全的 `:VaultEdit` scratch 流程：

```lua
require("ansible-vault").setup({
  auto_edit = true,
})
```

保存后插件会重新载入原始加密 buffer，并避免因为重新载入而再次触发自动编辑。

### 切换当前 buffer 状态

执行 `:VaultToggle` 可以在普通内容和 vault 密文之间切换。这个命令适合快速
查看，但要小心不要把解密后的 secret 误保存到磁盘。

### 对解密后的内容做 diff

将当前 buffer 与另一个 vault 文件比较：

```vim
:VaultDiff ../group_vars/prod/vault.yml
```

将当前文件与 Git 版本比较：

```vim
:VaultDiff --git HEAD
:VaultDiff --git main
```

两侧内容都会先解密到临时 nofile buffer，然后启用 Neovim diff 模式。普通
明文文件也可以参与比较，方便迁移或排查时使用。

### 查找 vault 文件

执行：

```vim
:VaultFiles view
:VaultFiles edit
:VaultFiles rekey
```

插件会扫描当前工作目录下首行为 Ansible Vault header 的文件。安装了
Telescope 时会自动使用 Telescope，否则回退到 `vim.ui.select`。如果希望始终
使用内置 picker，可以设置 `picker = "builtin"`。

### 查看状态信息

执行：

```vim
:VaultInfo
```

信息窗口会显示当前 buffer 是否加密、凭据来源、已配置的 vault label、
auto-edit/picker 设置、命令超时、密码缓存状态，以及最近一次成功的 vault
操作。

### 调整通知和超时

默认情况下，vault 命令 30 秒后超时。可以设置 `timeout_ms = 0` 关闭超时，
或者降低这个值以更快得到失败反馈：

```lua
require("ansible-vault").setup({
  timeout_ms = 10000,
  notify_success = false,
})
```

`notify_success = false` 只会静音成功后的 info 通知；错误和警告仍然会显示。

### 加密 YAML inline 字符串

在视觉模式中选中文本后执行：

```vim
:VaultEncryptString
```

如果选中的是完整 YAML 行：

```yaml
password: secret
```

插件会保留原来的 key，只加密 value：

```yaml
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

你也可以只选中 `password: secret` 里的 `secret`，插件同样会把加密结果插入
到 `password` 这个 key 下。

### 查看 YAML inline vault 字符串

选中 YAML vault block 后执行：

```vim
:VaultViewString
```

解密后的值会显示在只读浮窗中。按 `q` 或 `<Esc>` 关闭。

### 原地解密 YAML inline vault 字符串

选中 YAML vault block 后执行：

```vim
:VaultDecryptString
```

例如：

```yaml
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

会被替换为：

```yaml
password: secret
```

### 在光标下处理 inline vault 字符串

当光标位于普通 YAML key/value 行时，执行：

```vim
:VaultEncryptStringUnderCursor
```

当光标位于 YAML `!vault |` block 上时，执行：

```vim
:VaultViewStringUnderCursor
:VaultDecryptStringUnderCursor
```

插件会自动找到光标周围的 vault block，不需要手动选择整块内容。

### Rekey 加密文件

先配置 rekey 目标：

```lua
require("ansible-vault").setup({
  password_file = "~/.ansible/old-pass",
  rekey_password_file = "~/.ansible/new-pass",
})
```

然后打开加密文件并执行：

```vim
:VaultRekey
```

也可以直接传入 Ansible Vault rekey 参数：

```vim
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
:VaultRekey --new-vault-id prod@~/.ansible/prod-pass
```

buffer 必须是文件型、已加密且没有未保存修改。rekey 成功后，插件会重新载入
加密文件。

## 快捷键

插件不会默认设置快捷键。你可以自行添加：

```lua
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", "<cmd>VaultRekey<cr>", { desc = "Vault Rekey" })
vim.keymap.set("n", "<leader>vD", "<cmd>VaultDiff --git HEAD<cr>", { desc = "Vault Diff" })
vim.keymap.set("n", "<leader>vf", "<cmd>VaultFiles view<cr>", { desc = "Vault Files" })
vim.keymap.set("n", "<leader>vt", "<cmd>VaultToggle<cr>", { desc = "Vault Toggle" })
vim.keymap.set("v", "<leader>vs", "<cmd>VaultEncryptString<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("v", "<leader>vS", "<cmd>VaultDecryptString<cr>", { desc = "Vault Decrypt String" })
vim.keymap.set("v", "<leader>vv", "<cmd>VaultViewString<cr>", { desc = "Vault View String" })
vim.keymap.set("n", "<leader>vs", "<cmd>VaultEncryptStringUnderCursor<cr>", { desc = "Vault Encrypt String" })
vim.keymap.set("n", "<leader>vS", "<cmd>VaultDecryptStringUnderCursor<cr>", { desc = "Vault Decrypt String" })
```

## Statusline 集成

```lua
require("lualine").setup({
  sections = {
    lualine_x = {
      { require("ansible-vault").status },
    },
  },
})
```

也可以手动判断：

```lua
if require("ansible-vault").is_buffer_encrypted() then
  -- 当前 buffer 是 Ansible Vault 密文
end
```

## API

```lua
local vault = require("ansible-vault")

vault.is_encrypted(content)
vault.is_buffer_encrypted()
vault.encrypt()
vault.decrypt()
vault.view()
vault.edit()
vault.rekey()
vault.diff({ positionals = { "../other-vault.yml" } })
vault.diff({ git_ref = "HEAD" })
vault.files({ positionals = { "view" } })
vault.info()
local info_lines = vault.get_info()
vault.clear_password_cache()
vault.toggle()
vault.encrypt_string()
vault.decrypt_string()
vault.view_string()
vault.encrypt_string_under_cursor()
vault.view_string_under_cursor()
vault.decrypt_string_under_cursor()
vault.status()
```

## User Events

插件会在成功操作后触发 `User` autocmd。你可以监听具体事件，例如
`AnsibleVaultEncrypt`，也可以监听所有操作的 `AnsibleVaultOperation`：

```lua
vim.api.nvim_create_autocmd("User", {
  pattern = "AnsibleVaultOperation",
  callback = function(event)
    vim.print(event.data.operation)
  end,
})
```

当前事件包括 `AnsibleVaultEncrypt`、`AnsibleVaultDecrypt`、
`AnsibleVaultView`、`AnsibleVaultEditOpen`、`AnsibleVaultEditSave`、
`AnsibleVaultRekey`、`AnsibleVaultStringEncrypt`、
`AnsibleVaultStringDecrypt` 和 `AnsibleVaultDiff`。

## 安全说明

- 插件使用 argv list 执行命令，不通过 shell 字符串拼接，因此支持带空格的
  路径，也不会把配置值交给 shell 求值。
- 交互式密码通过 `inputsecret()` 获取，并在 vault 操作期间写入临时的 `0600`
  password file。
- `password_cache_ttl` 默认关闭。开启后，交互式密码会在过期前保存在 Neovim
  进程内存中，也可以通过 `:VaultClearPasswordCache` 主动清理。
- `VaultEdit` 使用 scratch `acwrite` buffer，并设置 `swapfile=false`、
  `undofile=false`、`bufhidden=wipe`。
- `VaultEdit` 会先写入同目录临时文件，再原子替换原文件。
- `VaultEdit` 会在检测到原文件被外部修改时拒绝覆盖。
- 查看或编辑时，解密内容仍然会存在于 Neovim 进程内存中。如果处理高敏感
  secret，请同时检查你的插件、剪贴板、backup、shada、终端录屏和会话记录。

## 开发

运行 headless 测试：

```sh
make test
```

测试使用 fake `ansible-vault` 可执行文件，因此不要求本机安装 Ansible。

使用 `uv` 运行真实二进制 smoke test：

```sh
make test-real
```

该命令会创建 `.venv`，安装 `ansible-core`，并让 Neovim 使用真实的
`.venv/bin/ansible-vault` 运行 smoke test。

## License

MIT
