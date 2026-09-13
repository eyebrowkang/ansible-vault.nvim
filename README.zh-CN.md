# ansible-vault.nvim

在 Neovim 中加密、解密、查看、编辑和轮换 Ansible Vault 文件及 YAML inline
`!vault` 值的密码，也可以直接新建加密文件。

English documentation: [README.md](README.md)

## 安装

- **Neovim 0.12**，其他版本不保证可用。
- **Ansible**，并确保 `ansible-vault` 在 `PATH` 中。安装方法见
  [官方安装指南](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)。
  如有需要，可设置下文的 `ansible_vault_path`。

使用 [lazy.nvim](https://github.com/folke/lazy.nvim)：

```lua
{ "eyebrowkang/ansible-vault.nvim" }
```

使用 packer.nvim：

```lua
use { "eyebrowkang/ansible-vault.nvim" }
```

`setup()` 可选。插件加载后六个命令就可用，不需要先准备密码文件。

在 v1.0.0 之前，命令、配置和行为可能变化，不保证兼容性或提供迁移支持。

## 快速上手

打开一个加密文件，执行：

```vim
:VaultEdit
```

没有配置凭据时，按提示输入 vault 密码。在独立 buffer 中编辑，再用 `:w` 加密保存
到原文件。成功写入会结束受保护的编辑会话，并返回刷新后的密文 buffer；如需再次编辑
明文，请重新执行 `:VaultEdit`。如再次提示，请重新输入密码；密码不会被缓存。`:wq`
和 `:x` 会等待实际保存结果，并且只在成功后关闭。

**想把明文保存到磁盘？** 使用 `:VaultDecrypt`，再 `:w`。
这次写入保存的就是**明文**，不会重新加密、再次询问密码或额外要求确认。

## 命令与保存

| 命令 | 整个文件 | inline YAML 值 |
|------|----------|----------------|
| `:VaultCreate[!] {file}` | 打开空的受保护 buffer；成功 `:w` 加密写入指定文件、销毁该 buffer 并显示密文 | 不适用 |
| `:VaultEncrypt` | 加密整个 buffer，再用 `:w` 保存 | 带 `[range]` 时加密一个值，然后保存源 YAML |
| `:VaultDecrypt` | 把密文替换成明文；`:w` 保存明文 | 把一个 `!vault` block 替换成明文；`:w` 按当前所见保存 YAML |
| `:VaultView` | 只读浮窗，禁止写入 | 单个值的只读浮窗，禁止写入 |
| `:VaultEdit` | 独立受保护 buffer；成功 `:w` 加密写回原文件、销毁该 buffer 并返回刷新后的密文 | 独立受保护 buffer；成功 `:w` **只**加密回填到源 buffer、销毁该 buffer 并返回源 buffer |
| `:VaultRekey` | 更换凭据，并把新密文保存到文件 | 更换一个 block 的凭据，然后保存源 YAML |

Create 和整文件 Edit 的保存目标**固定**，不能用 `:w other-file` 或 `:saveas`
改写到其他文件。inline Edit 在分屏窗口中打开该值，且不保存源文件：其受保护写入成功后
会关闭该分屏并返回源 buffer，再由你执行普通 `:w`。View 拒绝所有写入；按 `q` 或
`<Esc>` 关闭。

Create 或 Edit 成功保存会结束受保护的编辑会话；失败时 buffer 保持打开并保留修改，
可供重试。整文件 Edit 和 Rekey 要求文件已加密，且 buffer 没有未保存修改；`:wq` 和
`:x` 会等待保存完成。

### 选择作用目标

- Create 接受一个文件名，只用于文件。
- **不带 range 的 Encrypt 永远加密整个 buffer**，即使刚解密过一个 inline 值。
- Decrypt、View、Edit、Rekey：显式 range 选中一个 inline block；否则，第一行
  的 vault header 表示整个文件；若第一行没有 header，则使用光标所在的 `!vault`
  block。
- 之前的视觉选区不会被之后的普通模式命令复用。

加密普通文件，执行 `:VaultEncrypt`，再 `:w`。新建 vault：

```vim
:VaultCreate group_vars/prod/vault.yml
```

第一次成功 `:w` 之前不会创建文件；这次写入会关闭 Create scratch，并打开新的密文
文件。`:VaultCreate!` 允许替换已有文件，但不能使用已在其他 buffer 中打开的路径。

### inline YAML

加密当前行或视觉选区：

```vim
:.VaultEncrypt
:'<,'>VaultEncrypt
```

例如，`password: secret` 会变成：

```yaml
password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  3132333435...
```

选区必须正好包含一个完整标量。多行值要包括它的 key 和全部内容，但不要选中父级
或相邻条目：

```yaml
service:
  "private key": |-
    first line
    second line
```

这里应选中 `"private key"` 及其下两行。带引号的 key、缩进、列表项和值的内容会
保留，包括有意义的空白和换行。标量的呈现格式可能变化，但值不变。

要 View、Decrypt、Edit 或 Rekey 一个值，把光标放在 `!vault` block 内任意位置，
或选中完整 block。没有 key 的 block（包括列表项）也支持这四个命令。

inline Decrypt 之后，`:w` 会把明文值与仍加密的其他值一起保存。想再次只加密那个
值，请选中它的完整标量并执行 `[range]VaultEncrypt`，不要用不带 range 的
`:VaultEncrypt`。

inline Edit 会保留打开之前源 YAML 中已有的未保存修改。编辑该值期间，请勿改动
源 buffer：之后的源修改会阻止回填，即使改的是 block 之外的内容，`:w!` 也不能
越过这一冲突。恢复步骤见 `:help ansible-vault-troubleshooting`。

### 轮换密码

指定一种新凭据；旧凭据来自常规来源：

```vim
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
:VaultRekey --new-vault-id prod@~/.ansible/new-pass
```

这两个新凭据参数互斥。使用新密码文件默认保留原有 vault 标签；`--new-vault-id`
可选择新标签。Rekey 不接受 `--encrypt-vault-id`。整文件 Rekey 立即保存文件；
inline Rekey 只修改源 buffer，由你自行保存。

## 密码与配置

以下三种方式，按需选择。

### 1. 按提示输入密码

不需要 `setup()` 或密码文件。没有可用凭据来源时，插件会提示输入密码。也可以
为某次命令明确要求输入：

```vim
:VaultDecrypt --ask-vault-password
```

密码按操作重新获取，不会缓存。打开 Edit 会话和每次尝试 Edit/Create 写入都可能分别
提示输入；成功的 Create/Edit 写入会结束该会话。Decrypt 之后的保存不需要密码。

### 2. 使用现有密码文件或 vault ID

```lua
require("ansible-vault").setup({
  password_files = "~/.ansible/vault-pass",
})
```

或使用多个身份：

```lua
require("ansible-vault").setup({
  vault_ids = { "dev@~/.ansible/dev-pass", "prod@~/.ansible/prod-pass" },
  encrypt_vault_id = "prod",
})
```

`password_files` 和 `vault_ids` 都接受字符串或列表。同时设置时，
`password_files` 优先。也支持可执行的密码脚本。源为 `prompt` 或
`prompt_ask_vault_pass` 的 vault ID（包括从 Ansible 配置继承的）会在 Neovim 中
提示输入：每次操作重新提示，每个身份分别提示，不缓存。

可用配置共四项，均可省略：

| 配置 | 取值 | 默认值 |
|------|------|--------|
| `ansible_vault_path` | 可执行文件路径，如 `<env>/bin/ansible-vault` | `nil`：使用 `PATH` |
| `password_files` | 密码文件或文件列表 | `nil` |
| `vault_ids` | `label@source` 或身份列表 | `nil` |
| `encrypt_vault_id` | 用于加密的身份标签 | `nil`：复用适用的原有标签，否则由 Ansible 选择 |

有多个标签时，设置 `encrypt_vault_id` 选择身份。未知配置项或错误的值类型会报错，
且不改变当前配置。

### 3. 使用已有 Ansible 配置

可以省略 `setup()`，使用 `ANSIBLE_*` 环境变量或 `ansible.cfg`。配置文件按以下
顺序查找：

1. `$ANSIBLE_CONFIG`：文件，或包含 `ansible.cfg` / `.ansible.cfg` 的目录。
2. 从当前文件向上查找 `ansible.cfg` 或 `.ansible.cfg`；没有可用的文件目录时，
   从工作目录开始。
3. `~/.ansible.cfg`。
4. `/etc/ansible/ansible.cfg`。

配置文件中的路径相对于该配置文件解析。环境变量覆盖对应的 Ansible 配置项。

通常的凭据优先级为：**命令参数 → `setup()` 密码文件 → `setup()` vault ID →
Ansible 环境变量/配置 → 交互输入**。命令凭据替换本次操作所用的插件配置选择，
不会修改 `setup()`。

**提示输入的例外：** `--ask-vault-password` 要求交互输入。生效的
`ask_vault_pass = true` / `ANSIBLE_ASK_VAULT_PASS=true` 也优先于密码文件和
vault ID，包括命令行指定的凭据。如果希望改用文件，请关闭该设置。

六类命令参数、引号用法、标签选择和完整优先级，见
`:help ansible-vault-command-args` 与 `:help ansible-vault-passwords`。

## 快捷键

插件不设置默认快捷键。例如：

```lua
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
-- 视觉模式下用 `:` 把选区作为 range 传入。
vim.keymap.set("x", "<leader>ve", ":VaultEncrypt<cr>", { silent = true })
```

更多示例：`:help ansible-vault-keymaps`。

## 保护与限制

插件防止的是**非预期的明文副本**，不阻止你通过 Decrypt 主动保存明文。

- 受管理的明文 buffer 禁用 swap 文件和持久 undo，保存时不产生 Neovim 备份
  副本。View/Edit/Create 不创建明文编辑文件，交互式密码不写入文件。
- 保存明文后，当前 buffer 仍受保护。已保存的明文文件以后重新打开就是普通文件，
  不再作为受保护 vault 对待。
- 就地加密可能让持久 undo 在该 buffer 的剩余使用期间一直关闭，`:edit!` 也不
  恢复，即没有跨会话 undo；range 加密之后仍能在内存中撤销。重新载入可能清空
  undo 历史。详见 `:help ansible-vault-security`。
- 受保护 buffer 拒绝 `:1w file` 这样的部分写入和 `:w >> file` 这样的追加写入。
  对有文件名的已解密 buffer，即使随后执行 `:cd`，不带参数的 `:w` 仍写回原目标；
  要在当前目录创建明文副本，请用 `:w ./copy.yml`，或用 `:saveas ./name` 采用新目标。
  Edit/Create 的目标固定，View 完全禁止写入。
- 寄存器、ShaDa、剪贴板、其他插件、shell 命令和终端录制不在保护范围内。
  全局 `'shada'`、`'backup'`、`'writebackup'` 不会被修改。进程内存、操作系统
  swap、core dump 和其他系统级副本也不受保护。

## 排错

运行 `:checkhealth ansible-vault`，检查 Neovim、可执行文件、凭据来源及相关隐私
警告。检查不会询问密码。

- 找不到命令？确认插件管理器已经加载插件。
- 找不到可执行文件？安装 Ansible，或设置 `ansible_vault_path`。
- 密码来源不对？查看健康报告、`ANSIBLE_CONFIG` 和上文的提示输入例外。
- 保存被拒绝？保留编辑 buffer，检查源是否变化，以及是否使用了重定向或部分写入。
  不要为了重试就丢弃修改。

完整参考与恢复步骤：`:help ansible-vault.nvim` 和
`:help ansible-vault-troubleshooting`。

## License

MIT
