# ansible-vault.nvim

`ansible-vault.nvim` 是一个 Neovim 插件，用来在编辑器里处理 Ansible Vault 文件
和 YAML inline `!vault` 值。设计目标是：解密后的明文永远不落盘。

English documentation: [README.md](README.md)

## 功能

**隐私**

- 明文写入 buffer **之前**就关掉 `'swapfile'` 和 `'undofile'`，崩溃后磁盘上什么都不会留下
- 所有写入都由插件接管，`:w` 会先加密再落盘，Neovim 不会生成备份文件和 undo 文件
- 交互式密码通过子进程环境变量传递，密码本身永不写入磁盘
- 子进程输出绝不会被回显到错误信息里

**Vault 操作**

- 加密、解密、查看、编辑整个文件
- `:VaultCreate` 新建加密文件
- 通过选区或光标位置加密、查看、解密 inline `!vault` 值
- 对加密文件执行 rekey
- 将当前 buffer 解密后与另一个文件或 Git 版本做 diff
- 使用 Telescope 或内置 `vim.ui.select` 查找 vault 文件

**凭据**

- 像 ansible 一样读取 `ansible.cfg` 和 `ANSIBLE_*` 环境变量，并从当前文件向上查找
- 支持 password file、一个或多个 vault ID，或交互式输入
- 支持命令级凭据覆盖和命令行补全
- 可选：在内存中短时缓存交互式密码

**保真**

- 保留 `1.2` header 里的 vault ID 标签，不会静默降级成 `1.1`
- 支持 ansible 接受的全部 inline 写法：`|`、`|-`、`>`、`|2`、带引号的 key、列表项和任意嵌套

**集成**

- `:VaultInfo` 查看当前 buffer 和插件配置诊断信息
- `:checkhealth ansible-vault` 诊断
- 通过 `User` autocmd events 集成 statusline 或其他插件
- statusline 辅助函数会显示 vault ID 标签
- 支持通过 `conda run` 调用 Conda 环境中的 `ansible-vault`

## 依赖

- Neovim >= 0.12
- `ansible-vault` 可执行文件在 `PATH` 中，或通过配置指定路径/Conda 环境

### 版本支持策略

本插件**只跟随 Neovim 当前发行版**。为了把维护精力压到最低，这里不会为旧版本做兼容
处理，也不会针对旧版本测试。旧版本能不能跑不作保证；`:checkhealth ansible-vault`
会明确告诉你当前版本是否受支持。

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

插件按以下顺序解析凭据：

1. 命令级覆盖，例如 `:VaultEncrypt --vault-id prod@~/.prod-pass`
2. `setup()` 配置：先 `password_file`，再 `vault_ids`，再 `vault_id`
3. `ANSIBLE_*` 环境变量
4. `ansible.cfg`
5. 交互式密码输入

第 3、4 层是 ansible 自己的配置。凭据来自这两层时，插件**一个凭据参数都不传**，
只是把 `ansible-vault` 放到正确的目录下运行，让它自己去解析。这一点很关键：如果
`ansible.cfg` 里已经配了 `vault_password_file`，插件再传一个
`--vault-password-file`，`ansible-vault encrypt` 会直接失败：

```
The vault-ids default,default are available to encrypt
```

#### ansible.cfg 查找规则

ansible 只在**进程 cwd** 里找 `ansible.cfg`，不会向上递归。而在编辑器里 cwd 往往
不是 playbook 目录，所以插件改为从当前文件向上找：

1. `$ANSIBLE_CONFIG`（可以是文件，也可以是包含 `ansible.cfg` 的目录）
2. 从当前文件所在目录向上查找 `ansible.cfg` 或 `.ansible.cfg`
3. `~/.ansible.cfg`
4. `/etc/ansible/ansible.cfg`

随后 `ansible-vault` 会以命中的配置文件所在目录作为工作目录运行，这样配置里的
相对路径解析结果和 ansible 完全一致（相对于配置文件自身所在目录）。

会从 `[defaults]` 读取这些键，对应的环境变量优先级更高：`vault_password_file`、
`vault_identity_list`、`vault_identity`、`vault_encrypt_identity`、
`vault_id_match`、`ask_vault_pass`。

执行 `:VaultInfo` 可以看到命中了哪个配置文件、以及当前实际生效的凭据来源。

#### vault ID 标签会被保留

用 vault ID 加密的文件，header 里带着标签：

```
$ANSIBLE_VAULT;1.2;AES256;prod
```

如果直接用 `--vault-password-file` 重新加密，文件会被改写成
`$ANSIBLE_VAULT;1.1;AES256`，标签就丢了。插件会在解密前读出标签，重新加密时再显式
指定回去，所以 `:VaultEdit`、`:VaultDecrypt` + `:w`、`:VaultRekey` 都不会改变
header。

其余用法与英文文档一致，见 [README.md](README.md)。

## 命令

| 命令 | 说明 |
|------|------|
| `:VaultEncrypt` | 加密当前 buffer |
| `:VaultDecrypt` | 解密当前 buffer 进入编辑态，`:w` 会重新加密 |
| `:VaultCreate {file}` | 新建加密文件（`!` 覆盖已有文件）|
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
| `:VaultDecryptString` | 原地解密选中的 inline vault 字符串，`:w` 会还原 |
| `:VaultViewString` | 查看视觉选择中的 inline vault 字符串 |
| `:VaultEncryptStringUnderCursor` | 加密光标所在 YAML value |
| `:VaultViewStringUnderCursor` | 查看光标所在 inline vault block |
| `:VaultDecryptStringUnderCursor` | 原地解密光标所在 inline vault block |

## 健康检查

执行：

```vim
:checkhealth ansible-vault
```

健康检查会报告：

- `ansible-vault` 可执行文件，包括 `conda run` 包装
- 当前**实际生效**的凭据来源（与真实操作走同一份解析代码）
- 命中的 `ansible.cfg`、命中方式，以及 `ansible-vault` 将在哪个目录下运行
- password file 的可读性和权限，并把可执行的密码脚本识别为受支持的配置
- vault ID label 与 `encrypt_vault_id` 一致性
- `VaultRekey` 目标配置
- 交互式密码能否完全不落盘
- 仍可能持久化明文的全局选项，例如 `'shada'`

## 使用方式

### 加密普通文件

1. 打开普通 YAML 或文本文件。
2. 执行 `:VaultEncrypt`。
3. 确认结果后执行 `:write` 保存。

`:VaultEncrypt` 会把当前 buffer 内容替换为 Ansible Vault 密文，但不会自动
写入磁盘，这样你可以在保存前先检查结果。

### 解密文件并编辑

1. 打开以 `$ANSIBLE_VAULT` 开头的文件。
2. 执行 `:VaultDecrypt`。
3. 编辑解密后的内容。
4. 执行 `:write`。

`:VaultDecrypt` 会让 buffer 进入**明文编辑态**：buffer 里显示的是明文，但磁盘上
始终只有密文。

- 明文写入 buffer 之前就关掉 `'swapfile'` 和 `'undofile'`，已存在的 swap 文件会被
  立即删除
- `'buftype'` 变成 `acwrite`，因此 `:w`、`:wq`、`:x`，乃至 `:w 另一个文件`，全部由
  插件接管，都会先加密
- 因为 Neovim 完全不走自己的写入路径，所以不会生成备份文件，也不会写 undo 文件

写入之后 buffer 仍保持明文，方便继续编辑。执行 `:VaultEncrypt` 可以转回密文态并恢复
buffer 的常规行为，或者用 `:edit!` 重新载入加密文件。

`:VaultEdit` 仍然可用，效果相同，只是在单独的 scratch buffer 里进行，不动原 buffer。

### 新建加密文件

```vim
:VaultCreate group_vars/prod/vault.yml
```

这会打开一个空的、已加固的 buffer。文件在你执行 `:write` 之前不会被创建，而且只会以
密文形式写入。用 `:VaultCreate!` 覆盖已存在的文件。

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

如果希望打开加密文件时直接进入 `:VaultEdit` scratch 流程：

```lua
require("ansible-vault").setup({
  auto_edit = true,
})
```

保存后插件会重新载入原始加密 buffer，并避免因为重新载入而再次触发自动编辑。

### 切换当前 buffer 状态

执行 `:VaultToggle` 可以在普通内容和 vault 密文之间切换。用它解密同样会进入
`:VaultDecrypt` 的明文编辑态，所以 `:w` 依然会先重新加密。

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
vim.keymap.set("n", "<leader>vc", "<cmd>VaultCreate<cr>", { desc = "Vault Create" })
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", "<cmd>VaultRekey<cr>", { desc = "Vault Rekey" })
vim.keymap.set("n", "<leader>vD", "<cmd>VaultDiff --git HEAD<cr>", { desc = "Vault Diff" })
vim.keymap.set("n", "<leader>vf", "<cmd>VaultFiles view<cr>", { desc = "Vault Files" })
vim.keymap.set("n", "<leader>vt", "<cmd>VaultToggle<cr>", { desc = "Vault Toggle" })
vim.keymap.set("v", "<leader>vs", ":VaultEncryptString<cr>", { silent = true, desc = "Vault Encrypt String" })
vim.keymap.set("v", "<leader>vS", ":VaultDecryptString<cr>", { silent = true, desc = "Vault Decrypt String" })
vim.keymap.set("v", "<leader>vv", ":VaultViewString<cr>", { silent = true, desc = "Vault View String" })
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
vault.parse_header(content)  -- { version, cipher, label } 或 nil
vault.create({ positionals = { "group_vars/prod/vault.yml" } })
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
vault.status()  -- ""、"[VAULT]"、"[VAULT:prod]" 或 "[VAULT:decrypted]"
vault.cleanup() -- 丢弃进程内仍持有的全部密钥（VimLeavePre 时自动执行）
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
`AnsibleVaultView`、`AnsibleVaultCreate`、`AnsibleVaultEditOpen`、
`AnsibleVaultEditSave`、`AnsibleVaultPlaintextSave`、`AnsibleVaultRekey`、
`AnsibleVaultStringEncrypt`、`AnsibleVaultStringDecrypt` 和
`AnsibleVaultDiff`。

## 安全说明

目标是：解密后的明文永远不落盘，`kill -9` 和断电也一样。

**插件保证的部分**

- **不产生 swap 文件。** 明文进入 buffer 之前就复位 `'swapfile'`，这同时会立即删除该
  buffer 已存在的 swap 文件。
- **不产生 undo 文件。** 解密后的 buffer 关闭 `'undofile'`，并且每次密文↔明文切换都会
  清空 undo 历史。
- **不产生备份文件。** 解密后的 buffer 使用 `'buftype'` `acwrite`，Neovim 完全跳过自己的
  写入路径，`'backup'` 和 `'writebackup'` 都不会生效。
- **不可能误写明文。** 所有形式的 `:w` 都会经过插件并先加密，没有办法手工把明文写到磁盘上。
- **密码不落盘。** 交互式密码通过子进程环境变量传给 `ansible-vault`，由
  `stdpath("run")` 下一个**不含任何密钥**的静态辅助脚本读回。在无法这样做的平台上会退回到
  `0600` 临时文件，退出时删除，`:checkhealth` 会告诉你当前用的是哪种方式。
- **错误信息里不含密文/明文。** 子进程 stdout 绝不会被回显 —— `ansible-vault decrypt`
  可能先把明文写到 stdout 再以非零码退出。debug 日志会对凭据参数脱敏，且只走
  `vim.notify`，不往 stdout 打印。
- **argv 里没有明文。** 内容走 stdin，密码按引用传递，`ps` 里都看不到。
- **原子写入。** 密文先写到同目录的临时文件，`fsync` 后再 rename 就位，并继承原文件权限。

`make test-leak` 会实际验证前四条：在文件处于解密状态时 `kill -9` Neovim，然后到
Neovim 的 swap、undo、runtime 目录里搜索明文。

**仍然需要你自己注意的部分**

以下是插件刻意不去修改的全局选项。`:VaultInfo` 和 `:checkhealth ansible-vault` 在它们
开启时会给出警告：

- **`'shada'`** 会持久化寄存器。你从解密后的 buffer 或 `:VaultView` 浮窗里 *yank* 出来的
  文本，会在退出时写进 shada 文件。处理机密时可以考虑 `:set shada=`。
- **`'backup'`** 对不经过本插件的写入仍然生效。
- **明文在查看/编辑期间位于 Neovim 内存中**，因此可能进入操作系统 swap 分区或 core dump。
  如果这对你重要，请检查其他插件、剪贴板设置，以及终端/会话录制。
- **`:VaultDiff`** 在设置了 `'diffexpr'` 或 `'diffopt'` 不含 `internal` 时会拒绝执行，
  因为那种情况下 Neovim 会把两边内容都写到临时文件。

## 开发

运行 headless 测试：

```sh
make test        # 单元测试，使用假的 ansible-vault，不需要装 Ansible
make test-real   # 端到端测试，使用 .venv 里真实的 ansible-core（需要 uv）
make test-leak   # 解密到一半 kill -9 Neovim，然后搜索明文
make lint        # stylua --check 和 luacheck
make format      # stylua
```

`make test-real` 和 `make test-leak` 首次运行会创建 `.venv` 并安装 `ansible-core`。

提交信息规范见 [CONTRIBUTING.md](CONTRIBUTING.md)，release notes 由它生成。

## License

MIT
