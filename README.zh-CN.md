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

**凭据**

- 像 ansible 一样读取 `ansible.cfg` 和 `ANSIBLE_*` 环境变量，并从当前文件向上查找
- 支持一个或多个 password file / vault ID，或交互式输入
- 支持命令级凭据覆盖和命令行补全

**保真**

- 保留 `1.2` header 里的 vault ID 标签，不会静默降级成 `1.1`
- 支持 ansible 接受的全部 inline 写法：`|`、`|-`、`>`、`|2`、带引号的 key、列表项和任意嵌套

**集成**

- `:checkhealth ansible-vault` 诊断
- 通过一个 `User` autocmd event 集成 statusline 或其他插件

## 依赖

- Neovim >= 0.12
- `ansible-vault` 可执行文件在 `PATH` 中，或通过 `setup()` 指定路径

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
      password_files = "~/.ansible/vault-pass",
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
  -- --vault-id，可以是单个字符串，也可以是列表
  vault_ids = nil,

  -- --vault-password-file，可以是单个字符串，也可以是列表
  password_files = nil,

  -- 总是交互式询问密码，忽略其他已配置或自动发现的凭据。
  -- 不能与 vault_ids / password_files 同时使用。
  ask_password = false,

  -- --encrypt-vault-id：加密时使用哪个身份。
  -- 保持 nil 时，由 ansible-vault 根据已配置的 vault IDs 自行选择。
  encrypt_vault_id = nil,

  -- :VaultRekey 使用的 --new-vault-id，例如 "prod@~/.ansible/new-pass"
  new_vault_id = nil,

  -- :VaultRekey 使用的 --new-vault-password-file。
  -- 与 new_vault_id 互斥，和 ansible-vault 本身一致。
  new_password_file = nil,

  -- 自定义 ansible-vault 可执行文件路径
  ansible_vault_path = nil,
})
```

Conda 环境不需要专门的配置项，直接把 `ansible_vault_path` 指向该环境里的
可执行文件即可：

```lua
require("ansible-vault").setup({
  ansible_vault_path = "~/miniconda3/envs/ansible-dev/bin/ansible-vault",
})
```

### 密码来源

插件按以下顺序解析凭据：

1. 命令级覆盖，例如 `:VaultEncrypt --vault-id prod@~/.prod-pass`
2. `setup()` 配置：先 `ask_password`，再 `password_files`，再 `vault_ids`
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
`ask_vault_pass`。

执行 `:checkhealth ansible-vault` 可以看到命中了哪个配置文件、以及当前实际生效的凭据来源。

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
一共六个命令。每个命令既能作用于整个 vault 文件，也能作用于单个 inline
`!vault` 值；具体作用于哪一个，由 buffer、range 和光标位置共同决定。

| 命令 | 整文件 | inline `!vault` 值 |
|------|--------|--------------------|
| `:VaultEncrypt` | 加密当前 buffer | 给定 `[range]` 时，把这些行转成 `!vault` 值 |
| `:VaultDecrypt` | 解密进入编辑态，`:w` 重新加密 | 原地解密单个值，`:w` 会折回 |
| `:VaultView` | 只读浮窗查看解密内容 | 只读浮窗查看单个解密值 |
| `:VaultEdit` | 在 scratch buffer 中编辑，保存时加密 | — |
| `:VaultRekey` | 对文件执行 `ansible-vault rekey` | 用新凭据重新加密单个值 |
| `:VaultCreate[!] {file}` | 新建加密文件 | — |

### 作用目标的判定顺序

按顺序匹配，命中即停止：

1. 显式 `[range]` → 这些行，按 inline 值处理
2. buffer 正处于解密编辑态 → 沿用它当时的解密形态
3. 第一行是 `$ANSIBLE_VAULT` header → 整个文件
4. 要找「已加密的内容」→ 光标所在的 `!vault` block
5. 要找「待加密的内容」→ 整个 buffer

第 5 条解释了为什么用 `:VaultEncrypt` 加密单个值必须给 range：YAML 文件里几乎
每一行都是 `key: value`，靠光标猜测会在你想加密整个文件时悄悄只加密一行。
加密当前行用 `:.VaultEncrypt`。

以上判定完全不读 `'<`/`'>` 这两个 mark，因此在普通模式下执行命令，绝不会误用
你之前在 buffer 别处留下的视觉选区。

## 健康检查

执行：

```vim
:checkhealth ansible-vault
```

健康检查会报告：

- `ansible-vault` 可执行文件
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

### 加密 YAML inline 值

把要加密的行作为 range 传入——当前行，或一个视觉选区：

```vim
:.VaultEncrypt
:'<,'>VaultEncrypt
```

如果是 `key: value` 行：

```yaml
password: secret
```

插件会保留原来的 key，只加密 value：

```yaml
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

### 查看、编辑、rekey inline vault 值

把光标放在 `!vault` block 内的任意位置即可，不需要选中整块内容——插件会自动
找到光标所在的 block：

```vim
:VaultView     " 只读浮窗
:VaultDecrypt  " 原地解密以便编辑
:VaultRekey    " 用新凭据重新加密这一个值
```

执行 `:VaultDecrypt` 后，buffer 进入 **inline 明文态**：解密区域用 extmark 跟踪，
buffer 的加固方式与整文件解密完全一致，`:w` 会先把该值折回 `!vault` block 再写盘。
周围的行原样写出，所以部分加密的文件也能正常处理。同一文件中的其他值仍保持加密，
也可以继续解密。

不带 range 执行 `:VaultEncrypt` 会把已解密的值折回密文，但不写盘——它是
`:VaultDecrypt` 的逆操作，和整文件的情况一样，`:w` 仍然由你决定。

对 inline 值执行 `:VaultRekey` 必须「用旧凭据解密、再用新凭据加密」，因为
`ansible-vault rekey` 只接受文件路径。明文在整个过程中只存在于一个局部变量里：
不会进入 buffer、buffer 变量、通知消息或事件数据。

### Rekey 加密文件

先配置 rekey 目标：

```lua
require("ansible-vault").setup({
  password_files = "~/.ansible/old-pass",
  new_password_file = "~/.ansible/new-pass",
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

`1.2` header 里的 vault ID 标签会被保留：插件会把标签放在新身份上，即
`--new-vault-id prod@<新 password file>`。插件绝不会给 `rekey` 传
`--encrypt-vault-id`——在这个子命令下，该参数是从「以**旧**身份为基础的候选集」里
挑选**新**密钥，结果要么直接报错，要么用旧密码重新加密却依然报告成功。

## 快捷键

插件不会默认设置快捷键。你可以自行添加：

```lua
vim.keymap.set("n", "<leader>vc", "<cmd>VaultCreate<cr>", { desc = "Vault Create" })
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", "<cmd>VaultRekey<cr>", { desc = "Vault Rekey" })

-- 视觉模式是通过 range 把选区传给命令的，所以这里必须用 `:` 形式，
-- 用 `<cmd>` 不会带上 range。
vim.keymap.set("x", "<leader>ve", ":VaultEncrypt<cr>", { silent = true, desc = "Vault Encrypt" })
vim.keymap.set("x", "<leader>vd", ":VaultDecrypt<cr>", { silent = true, desc = "Vault Decrypt" })
vim.keymap.set("x", "<leader>vv", ":VaultView<cr>", { silent = true, desc = "Vault View" })
```

六个命令同时覆盖两种作用域，所以每个动作一个快捷键就够了：普通模式下作用于整个
文件，视觉模式下作用于 inline 值。

## Statusline 集成

使用 `is_buffer_encrypted()`：它每次都会检查 buffer 内容，而不依赖之前某次操作
留下的状态。

```lua
require("lualine").setup({
  sections = {
    lualine_x = {
      {
        function()
          return require("ansible-vault").is_buffer_encrypted() and "[VAULT]" or ""
        end,
      },
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
-- 每个动作都接受与命令相同的作用域提示：传 range 作用于 inline 值，
-- 不传则作用于整个 buffer 或光标所在的 block。
vault.encrypt(nil, { range = 1, line1 = 7, line2 = 7 })
vault.decrypt()
vault.encrypt_string_under_cursor()
vault.view_string_under_cursor()
vault.decrypt_string_under_cursor()
vault.cleanup() -- 丢弃进程内仍持有的全部密钥（VimLeavePre 时自动执行）
```

## User Events

插件会在成功操作后触发 `User` autocmd，pattern 只有一个 `AnsibleVaultOperation`：

```lua
vim.api.nvim_create_autocmd("User", {
  pattern = "AnsibleVaultOperation",
  callback = function(event)
    vim.print(event.data.op, event.data.scope)
  end,
})
```

事件 `data` 中带有 `op`（`"encrypt"`、`"decrypt"`、`"view"`、`"edit"`、
`"save"`、`"rekey"`、`"create"`）、`scope`（`"file"` 或 `"inline"`），以及对应的
buffer 和文件路径。只有一个 pattern，因此一个 autocmd 就能响应全部操作，再按
`op`/`scope` 过滤即可。

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
  可能先把明文写到 stdout 再以非零码退出。插件确实会展示的 argv 都已对凭据值脱敏，且只走
  `vim.notify`，不往 stdout 打印。
- **argv 里没有明文。** 内容走 stdin，密码按引用传递，`ps` 里都看不到。
- **原子写入。** 密文先写到同目录的临时文件，`fsync` 后再 rename 就位，并继承原文件权限。

`make test-leak` 会实际验证前四条：在文件处于解密状态时 `kill -9` Neovim，然后到
Neovim 的 swap、undo、runtime 目录里搜索明文。

**仍然需要你自己注意的部分**

以下是插件刻意不去修改的全局选项。`:checkhealth ansible-vault` 在它们
开启时会给出警告：

- **`'shada'`** 会持久化寄存器。你从解密后的 buffer 或 `:VaultView` 浮窗里 *yank* 出来的
  文本，会在退出时写进 shada 文件。处理机密时可以考虑 `:set shada=`。
- **`'backup'`** 对不经过本插件的写入仍然生效。
- **明文在查看/编辑期间位于 Neovim 内存中**，因此可能进入操作系统 swap 分区或 core dump。
  如果这对你重要，请检查其他插件、剪贴板设置，以及终端/会话录制。

## 从 v0.1.0 迁移

v0.2.0 是一次有意的破坏性变更：移除边缘集成、合并重叠的接口，而不是保留兼容别名。
这里没有「废弃但仍可用」的东西——被移除的名字就是不存在了。

### 命令

| v0.1.0 | v0.2.0 |
|--------|--------|
| `:VaultEncryptString` | `:'<,'>VaultEncrypt` |
| `:VaultEncryptStringUnderCursor` | `:.VaultEncrypt` |
| `:VaultViewString`、`:VaultViewStringUnderCursor` | `:VaultView`（光标在 block 内）|
| `:VaultDecryptString`、`:VaultDecryptStringUnderCursor` | `:VaultDecrypt`（光标在 block 内）|
| `:VaultToggle` | `:VaultEncrypt` 或 `:VaultDecrypt` |
| `:VaultClearPasswordCache` | 已移除——密码不再缓存 |
| `:VaultInfo` | `:checkhealth ansible-vault` |
| `:VaultDiff` | 已移除——请对解密后的副本使用 diff 工具 |
| `:VaultFiles` | 已移除——请使用你的模糊查找插件 |

### 配置项

| v0.1.0 | v0.2.0 |
|--------|--------|
| `password_file = "p"` | `password_files = "p"`（也接受列表）|
| `vault_id = "prod@p"` | `vault_ids = "prod@p"`（也接受列表）|
| `rekey_password_file` | `new_password_file` |
| `rekey_vault_id` | `new_vault_id` |
| `conda_env = "env"` | `ansible_vault_path = "<env>/bin/ansible-vault"` |
| `password_cache_ttl` | 已移除——每次操作都询问 |
| `timeout_ms` | 已移除——改为内部固定值 |
| `notify_success` | 已移除 |
| `auto_detect`、`auto_edit` | 已移除——请显式执行命令 |
| `picker` | 随 `:VaultFiles` 一起移除 |
| `debug` | 已移除 |
| `vim.g.ansible_vault_config` | 请调用 `setup()` |

未知配置键现在会直接报错，而不是被忽略，所以遗留的配置项会明确告诉你，而不是看起来
还在生效。

### 命令参数

`--vault-pass-file` 和 `--password-file` 已移除，请统一使用
`--vault-password-file`（现在可以重复传入）。裸标签简写
（`:VaultEncryptString prod`）已移除，请写 `--encrypt-vault-id prod`。新增
`--ask-vault-password`。无法识别的参数会直接报错。

### API 与事件

`toggle`、`diff`、`files`、`info`、`get_info`、`status`、`clear_password_cache`
以及全部 `*_string*` / `*_under_cursor` 函数均已移除；六个动作改为通过 `opts` 中的
`range`/`line1`/`line2` 指定作用域。11 个 `AnsibleVault*` 事件合并为
`AnsibleVaultOperation`，`op` 和 `scope` 放在 `event.data` 里。statusline 请用
`is_buffer_encrypted()` 替代 `status()`。

### 值得注意的行为变化

- 不再支持字符级（charwise）和块级（blockwise）inline 加密；range 一律按整行处理。
- `:VaultRekey` 不再传 `--encrypt-vault-id`。如果你之前依赖旧行为，请检查带标签的
  文件是否真的完成了轮换——旧代码可能用**旧密码**重新加密并报告成功。

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
