# ansible-vault.nvim

在 Neovim 里处理 Ansible Vault 文件和 YAML inline `!vault` 值：保存语义明确，
并防止产生非预期的明文副本。

English documentation: [README.md](README.md)

## 功能

- 用六个编辑器命令覆盖 `ansible-vault` 全部七个子命令的能力：create、encrypt、
  decrypt、view、edit、rekey，以及通过 `:VaultEncrypt` 加 range 实现的
  inline `encrypt_string`。
- **Decrypt 就是解密。** 整文件和 inline 的 `:VaultDecrypt` 都会把密文替换成
  当前 buffer 里的明文；`:w` 保存的就是明文，不会重新加密、不会再问一次密码、
  也不会额外要求确认。
- **Edit 让文件始终保持加密。** `:VaultEdit` 使用独立的受保护 scratch buffer。
  整文件保存时加密写回原文件；inline 保存时只把这一个值加密回填到源 buffer，
  源文件仍由你自己保存。
- 整文件与 inline 的只读查看、新建加密文件，以及两种作用域下的密码轮换。
- inline 的 YAML key、缩进、列表项和多行标量值，在加密、解密、编辑和 rekey
  的整个往返过程中都被保留。
- 从当前文件向上查找 `ansible.cfg`、读取 `ANSIBLE_*` 设置、支持多个 password
  file 或 vault ID，以及命令级凭据覆盖。
- 受保护的明文 buffer、不产生明文编辑临时文件、交互式密码不落盘，以及一份精简的
  `:checkhealth ansible-vault` 报告。

这些都是编辑器内的工作流，而不是去调起 Ansible 的 `$EDITOR`、或为原生 `edit`
和 `create` 生成明文临时文件的包装。查看同样只把明文留在内存里。详见
[安全性](#安全性)。

## 依赖

- Neovim 当前发行版（目前是 0.12）。
- `ansible-vault` 在 `PATH` 中，或把它的路径传给 `setup()`。

### 版本支持策略

本插件**只跟随 Neovim 当前发行版**。这里不会为旧版本做兼容处理，也不会针对旧版本
测试；旧版本能不能跑不作保证。只盯一个目标，维护成本才压得住。
`:checkhealth ansible-vault` 会告诉你当前版本是否受支持。

### v1.0.0 前的稳定性政策

**在 v1.0.0 发布之前，本插件不提供任何兼容性或迁移保证。**
任何版本都可能变更或移除命令、配置和行为，不保证提供弃用过渡期、兼容别名、
迁移工具或迁移指南。

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

插件加载后六个命令就可用，`setup()` 是可选的。唯一的 Lua 入口是
`require("ansible-vault").setup(opts)`。完整的命令参考见
`:help ansible-vault.nvim`。

## 命令

| 命令 | 整个文件 | inline YAML 值 |
|------|----------|----------------|
| `:VaultCreate[!] {file}` | 空的受保护 buffer；`:w` 加密写入目标 | — |
| `:VaultEncrypt` | 把整个 buffer 替换为密文，由你保存 | 显式 `[range]` 加密一个 YAML 值，由你保存源文件 |
| `:VaultDecrypt` | 把密文替换成明文；`:w` 保存明文 | 把一个 `!vault` block 替换成明文值；`:w` 按当前所见保存源文件 |
| `:VaultView` | 只读浮窗 | 单个值的只读浮窗 |
| `:VaultEdit` | 独立 scratch；`:w` 加密写回原文件 | 独立 scratch；`:w` 只把这一个 block 加密回填到源 buffer |
| `:VaultRekey` | 原生 rekey，把新密文发布到文件 | 用新凭据重新加密一个 block，由你保存源文件 |

### 作用目标如何决定

- `:VaultCreate` 总是需要一个文件名。
- `:VaultEncrypt` **不带 range 时永远加密整个 buffer**，即使刚刚解密过某个
  inline 值也一样。带显式 range 时加密一个 YAML 值。
- Decrypt、View、Edit、Rekey：显式 range 选中一个 inline block；否则第一行的
  vault header 表示整个文件；否则取光标所在的 `!vault` block。

inline range 必须正好覆盖一个完整的值或 block，不能是截断的 block、多个值，
或夹带相邻的 YAML 条目。加密当前行用 `:.VaultEncrypt`；多行标量要连同它的 key
和全部内容一起选中。无法解析的选区会在改动 buffer 之前直接报错。

命令不读取陈旧的 `'<`/`'>` mark。`:'<,'>VaultEncrypt` 这样的视觉模式命令是显式
传入 range 的；之后在普通模式下执行命令不会复用那个选区。

## 使用方式

### 加密或解密整个文件

加密普通文件：执行 `:VaultEncrypt`，检查密文，然后 `:w`。加密改变的是 buffer，
不是磁盘上的文件。

把一个 vault 以明文写出：

1. 打开加密文件，执行 `:VaultDecrypt`。
2. 需要的话编辑明文。
3. 执行 `:w`，把**明文**保存到文件。

这次写入没有重新加密、没有第二次密码提示、也没有额外确认。如果文件在解密之后
在磁盘上发生了变化，这次保存会被拒绝，直到你用 `:w!` 确认。

在有文件名的 buffer 里，`:w another-file.yml` 写出的是一份明文副本，buffer 自身
仍算未保存——那份副本不是这个 buffer 的文件。而在没有文件名的 buffer 里，写入
没有「另一个文件」可言，所以 `:w some-file.yml` 就是保存这个 buffer 本身：它会
采纳这个文件名并被标记为已保存，和普通 buffer 的行为一致。

明文保存之后，当前 buffer 仍然处于受保护状态。但这个普通明文文件在以后的会话里
重新打开就只是个普通文件：插件不保存任何历史或元数据来标记它曾是 vault。

想让磁盘上重新变成密文，执行 `:VaultEncrypt` 再 `:w`。经历过「就地解密再加密」
的 buffer 会在其余生保持持久 undo 关闭，因此没有跨会话 undo；原因以及
`:edit!` 为什么解除不了它，见[安全性](#安全性)。如果你希望全程保持文件加密，请改用
`:VaultEdit`。`:edit!` 会丢弃 buffer 修改并重新载入磁盘上的当前内容——在明文
保存之后，那就是明文。

### 新建加密文件

```vim
:VaultCreate group_vars/prod/vault.yml
```

这会打开一个空的受保护 buffer。目标文件在 `:w` 之前不会被创建，而且这个 buffer
的保存只写密文。`:VaultCreate!` 允许替换已存在的文件，但在第一次成功保存之前
同样不会覆盖它。如果该路径已经在别的 buffer 里打开，命令会直接报告，而不是把它
清空。

### 查看但不修改源

在整个 vault 上、或把光标放进 inline `!vault` block 里执行 `:VaultView`。明文会
出现在一个受保护的只读浮窗中，按 `q` 或 `<Esc>` 关闭并丢弃。查看不会改动源
buffer，也不会把明文写到临时文件。

这个浮窗拒绝把自己写到任何地方：`:w`、`:w {path}`、`:saveas` 和 `:%w {path}`
全部报错，和 Edit 或 Create 的 buffer 一致。View 是只读动作；想把解密内容落盘，
请用 `:VaultDecrypt` 明确提出这个要求。

### 在保持文件加密的前提下编辑

在一个没有未保存修改、由文件支撑的整体 vault 上执行 `:VaultEdit`。插件会把明文
放进一个独立的受保护 scratch buffer。`:w` 加密并原子写入原文件；scratch 会继续
保留，所以你可以接着编辑并再次保存。结束时用 `:q` 或 `:wq`。

目标是固定的：对 Edit 和 Create 的 buffer 来说，用 `:w other-file` 重定向写入
都是错误，既不是导出，也不会被悄悄改写到真正的目标上。编辑期间源 buffer 或源
文件发生变化时，保存会被拒绝，而不是覆盖这些变化。在 Edit scratch **内部**解密
一个 inline 值，只是在明文里再加一段明文，并不会把这个 scratch 变成会以明文保存
自己的 buffer。

打开 Edit 与之后的每次保存都是各自独立的凭据操作。交互式密码不会被缓存，所以
打开和保存可能各自提示一次。`:wq` 和 `:x` 会等待加密与写入完成；保存失败不会
关闭 scratch，也不会丢弃其中的修改。

### 加密一个 inline YAML 值

把当前行或视觉选区作为 range 传入：

```vim
:.VaultEncrypt
:'<,'>VaultEncrypt
```

例如 `password: secret` 会变成：

```yaml
password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  3132333435...
```

key 保持原样，只有 value 被加密。多行值要选中完整的标量：

```yaml
service:
  "private key": |-
    first line
    second line
```

选中 `"private key"` 和它的两行内容，而不是 `service:` 或它的相邻行。inline
工作流保留带引号的 key、嵌套、列表前缀和值的内容，包括有意义的前导空白和末尾
换行。YAML 标量的呈现形式可能变化，但值本身不变：解密时可能用字面块标量来表示
多行内容。一个完整的已解密标量可以再次被选中并加密。源 YAML 要你自己用 `:w`
保存。

### 解密、编辑或 rekey 单个 inline 值

把光标放在 `!vault` block 内的任意位置，或显式选中整个 block：

```vim
:VaultView
:VaultDecrypt
:VaultEdit
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
```

**Decrypt** 会把这个 block 替换成源 buffer 里的一个明文 YAML 值，其他值不变。
`:w` 按当前所见写出这份 YAML，包括已解密的那个值；它不会自动把值折回 `!vault`
block。想再次只加密那个值，选中它完整的标量并使用 `[range]VaultEncrypt`。不带
range 的 `:VaultEncrypt` 加密的是整个 YAML buffer。

**Edit** 只在一个独立的受保护 scratch 里打开这一个值。`:w` 把它加密回填到源
buffer，**但不写源 YAML 文件**。你需要回到源 buffer 自己保存。Edit 打开之前
源里已经存在的其它未保存修改会被原样保留。

Edit 打开之后，源 buffer 的任何改动都会被保守地当作冲突，即使改的是选中 block
之外的地方。源 buffer 的身份变化或被销毁同样会阻止回填。插件不会尝试在这些编辑
之间重新定位 block。

这一类拒绝刻意**没有** `:w!` 逃生口。`:w!` 确实可以覆盖**源文件**那一项检查，
因为 inline 回填只改 buffer，磁盘上变化了的文件不会因此受损。而块快照检查问的是
另一个问题——这个 block 还在原来的位置吗？`!` 给不出正确的位置，强行写入等于覆盖
现在恰好落在那里的某个值。正确的出路是对该 block 重新执行 `:VaultEdit`：scratch
里的明文不会丢，你可以把它带过去。

成功回填之后，你可以继续编辑并基于更新后的快照再次保存 scratch。

**Rekey** 在内存里解密该值并用新凭据加密，然后只替换那一段密文 block。中间明文
绝不会被插入源 buffer。结果 YAML 由你自己保存。

Edit 和 Rekey 需要一个 YAML key 才能把重新加密后的值放回去，所以没有 key 的
`!vault` block 会被拒绝；View 和 Decrypt 仍然可用。

### 轮换整个文件的密码

打开一个没有未保存修改、由文件支撑的整体 vault，并给出新凭据：

```vim
:VaultRekey --new-vault-password-file ~/.ansible/new-pass
:VaultRekey --new-vault-id prod@~/.ansible/new-pass
```

两个新凭据参数互斥。旧凭据来自常规凭据来源或命令级覆盖。Rekey 在一个权限受限的
**密文**暂存文件上运行 Ansible 原生的 `rekey`，只有在原文件未发生变化时才原子
发布结果。随后 buffer 会显示新密文。失败时原 vault 保持完好。

使用新 password file 时 `1.2` header 的标签会被保留；显式的 `--new-vault-id`
则指定新标签。原生 rekey 不使用 `--encrypt-vault-id`：标签是放在**新**身份上
给出的，这样轮换才真的用上新密码。继承而来的加密身份默认值会在这次子进程操作
的范围内被隔离，不会改动你的配置或全局环境。

## 配置与凭据

`setup()` 接受这四项设置：

```lua
require("ansible-vault").setup({
  ansible_vault_path = nil, -- 可执行文件路径；nil 表示用 PATH
  password_files = nil,     -- --vault-password-file：字符串或列表
  vault_ids = nil,          -- --vault-id：字符串或列表
  encrypt_vault_id = nil,   -- 加密身份的标签
})
```

未知的键和非法的值都会报错，并且不会改动当前配置。要使用 Conda 或其他环境，把
`ansible_vault_path` 指向 `<env>/bin/ansible-vault`。

多个 vault 身份：

```lua
require("ansible-vault").setup({
  vault_ids = {
    "dev@~/.ansible/dev-pass",
    "prod@~/.ansible/prod-pass",
  },
  encrypt_vault_id = "prod",
})
```

`password_files` 同样接受字符串或列表。两项凭据配置同时存在时，
`password_files` 优先。没有显式指定加密标签时由 Ansible 选择身份；有多个身份
时请用 `encrypt_vault_id` 消除歧义。Edit 会保留文件原有的 `1.2` vault 标签，
除非你显式选择了别的加密身份。Decrypt 写出的是明文，所以它的保存没有 vault
header 可以保留。

### 凭据优先级

1. 命令级凭据覆盖。
2. `setup()` 配置的凭据：先 `password_files`，再 `vault_ids`。
3. `ANSIBLE_*` 环境变量。
4. `ansible.cfg`。
5. 没有任何凭据来源时，交互式输入密码。

命令级凭据覆盖是**替换**已配置的凭据选择，而不是追加。重复的参数构成这次操作
的列表，不会保留已配置列表里未被提到的条目。覆盖不会修改 `setup()` 的配置。
对于来自环境变量和配置文件的凭据，插件让 Ansible 自己解析，而不是把它们再作为
CLI 参数传一遍。

### 命令参数

| 参数 | 用途 |
|------|------|
| `--vault-password-file {path}` | 凭据文件；可重复 |
| `--vault-id {label@source}` | vault 身份；可重复 |
| `--ask-vault-password` | 本次命令改为提示输入，忽略已配置或自动发现的凭据 |
| `--encrypt-vault-id {label}` | Encrypt、Create、Edit 的加密身份 |
| `--new-vault-password-file {path}` | Rekey 的新 password file |
| `--new-vault-id {label@source}` | Rekey 的新身份 |

每个参数只被真正用得上它的命令接受，所以一个不可能生效的参数会报错，而不是变成
静默的空操作。特别是 `:VaultRekey` 不接受 `--encrypt-vault-id`：在 Ansible 的
`rekey` 下，这个参数是从以**旧**身份为基础的候选集里挑选的，接受它就可能让一次
轮换报告成功、而文件仍留在旧密码上。

提示输入密码和 rekey 的新凭据都是命令参数，不是持久的 `setup()` 选项。不要同时
给出互相竞争的凭据选择器，也不要同时给出两个新凭据参数。未知参数、缺少取值、
该命令不适用的参数以及多余的位置参数都会报错；Create 只接受一个文件名。

路径可以加引号或用反斜杠转义：

```vim
:VaultView --vault-password-file '/path with spaces/pass'
:VaultEdit --vault-password-file /path\ with\ spaces/pass
:VaultEncrypt --vault-id dev@~/.dev-pass --vault-id prod@~/.prod-pass --encrypt-vault-id prod
:VaultDecrypt --ask-vault-password
:VaultCreate 'group_vars/prod/private vault.yml'
```

补全提供该命令支持的参数，以及 Create 的文件名。

### ansible.cfg 查找

向上查找是一项核心的编辑器适配：Ansible 只看进程的工作目录，而那未必是你正在
编辑的文件所在的目录。插件按以下顺序查找：

1. `$ANSIBLE_CONFIG`（可以是文件，也可以是包含 `ansible.cfg` 的目录）。
2. 从当前文件向上查找 `ansible.cfg` 或 `.ansible.cfg`。
3. `~/.ansible.cfg`。
4. `/etc/ansible/ansible.cfg`。

子进程会在命中的配置目录下运行，这样配置里的相对路径就按 Ansible 的预期解析，
也就是相对于配置文件自身。相关的 `[defaults]` 键是 `vault_password_file`、
`vault_identity_list`、`vault_identity`、`vault_encrypt_identity` 和
`ask_vault_pass`；对应的环境变量优先。

### 健康检查

```vim
:checkhealth ansible-vault
```

报告覆盖 Neovim 版本支持、可执行文件、配置与凭据来源，以及必要的隐私警告。它
不会为了做诊断而提示输入密码或创建交互式密码辅助脚本。

## 快捷键

插件不会默认设置快捷键。例如：

```lua
vim.keymap.set("n", "<leader>vc", ":VaultCreate ", { desc = "Vault Create" })
vim.keymap.set("n", "<leader>ve", "<cmd>VaultEncrypt<cr>", { desc = "Vault Encrypt" })
vim.keymap.set("n", "<leader>vd", "<cmd>VaultDecrypt<cr>", { desc = "Vault Decrypt" })
vim.keymap.set("n", "<leader>vv", "<cmd>VaultView<cr>", { desc = "Vault View" })
vim.keymap.set("n", "<leader>vE", "<cmd>VaultEdit<cr>", { desc = "Vault Edit" })
vim.keymap.set("n", "<leader>vr", ":VaultRekey ", { desc = "Vault Rekey" })

-- 视觉模式下用 `:` 把选区作为显式 range 传给命令。
vim.keymap.set("x", "<leader>ve", ":VaultEncrypt<cr>", { silent = true })
vim.keymap.set("x", "<leader>vd", ":VaultDecrypt<cr>", { silent = true })
vim.keymap.set("x", "<leader>vv", ":VaultView<cr>", { silent = true })
vim.keymap.set("x", "<leader>vE", ":VaultEdit<cr>", { silent = true })
```

Create 和 Rekey 的映射会把命令行留着，好让你补上文件名或新凭据。普通模式下的
Decrypt、View、Edit、Rekey 按上面的目标规则工作；视觉模式用 `<cmd>` 形式是传不
上 range 的。

## 安全性

隐私目标是避免**非预期的副本**，而不是禁止一次明确的明文保存。`:VaultDecrypt`
之后的 `:w` 就是有意写出明文。View 没有任何明文保存路径，Edit/Create 的临时
buffer 通过各自受控的写入器只保存密文。

- **明文进入之前先加固。** 受管理的明文 buffer 在明文到达之前就关掉
  `'swapfile'` 和 `'undofile'`。复位 `'swapfile'` 会删除该 buffer 已存在的 swap
  文件。明文与密文之间的每次转换所保证的是**明文不会进入 undo 文件**——有时靠
  清空 undo 历史，有时靠让 `'undofile'` 永久关闭，这与「undo 历史总是被清空」
  并不是一回事。例如在 `[range]VaultEncrypt` 之后，`:undo` 仍然可以把你刚刚
  加密掉的值取回**内存**；但该 buffer 的 `'undofile'` 已被永久关闭，所以它写不
  出去。
- **受控写入，不产生 Neovim 备份副本。** 可写的受管理 buffer 使用 `'buftype'`
  `acwrite`，绕开 Neovim 常规的写入/备份路径。Decrypt 的写入器按设计保存明文，
  Edit/Create 的写入器加密。把一个已解密的 buffer 保存为明文，不会解除它当前的
  buffer 保护。只加密一个 range 并不能证明 buffer 其余部分不含明文；只有整个
  buffer 加密成功才会恢复常规写入行为，而且即便如此也不包括 `'undofile'`
  （见下一条）。
- **不允许部分写入与追加写入。** `acwrite` 能覆盖 `:w`、`:w {file}` 和
  `:saveas`，但覆盖不到按行范围的部分写入和追加写入。这两种写入没有处理器时，
  Neovim 会自己把那些行写出去：不加密、不走原子写，权限也是 umask 决定的而不是
  `0600`。因此 `:1w {file}` 和 `:w >> {file}` 会被直接拒绝，受管理 buffer 和
  View 浮窗都是如此。而从已解密 buffer 发出的**整个 buffer** 的 `:w {path}`
  是你主动要求的保存，仍然走原子写：新建文件是 `0600`，已存在的目标沿用它自己
  原有的权限。

  这种拦截并不是完备的，而既然上面已经逐条列出了哪些路径**被**覆盖，这个缺口就
  值得点明：把 buffer 通过 shell 管道写出——`:w !cat > f`、`:1,2w !cat > f`、
  `:%!tee f`——不会触发任何插件能挂钩的事件，因此这些命令会按 shell 的方式把明文
  写出去，权限通常是 `0644`。这被视为你明确下达的指令，而不是泄漏，与开着
  `'shada'` 从解密 buffer 里 yank 属于同一类。
- **只有在可证明安全时才交还持久 undo。** 仅仅在明文进入 buffer 期间
  关闭 `'undofile'` 是不够的：在下一次常规写入时，Neovim 会把某次变更所
  **替换掉的**文本序列化出去，于是一个先就地解密、再就地加密的 buffer 会把它
  刚刚加密掉的明文写进持久 undo 文件——而磁盘上的那个文件从头到尾只有密文。
  因此，只有当 undo 历史本身已经被丢弃之后，恢复 `'undofile'` 才是安全的；
  真正的前提就是这一点：插件先清掉 undo 历史，然后才把持久 undo 交还。单靠
  「一次读取替换了 buffer 内容」**并不足够**，因为那次 reload 本身也是一次可撤销
  的变更，仍然握着它替换掉的明文。

  净结果分两种情况。在插件仍在管理该 buffer 时发生的 reload，会先清 undo 历史，
  因此能拿回跨会话 undo。而经历过**就地**解密再加密的 buffer 会在其余生保持
  `'undofile'` 关闭，没有跨会话 undo；`:edit!` 也不会把它恢复，因为那套恢复逻辑
  只在「仍持有活动 session 的那次 reload」时运行。这些都是 buffer 局部选项，
  所以之后为同一个文件新开的 buffer 不受影响。两种情况下，会话**内**的 undo
  都不受影响。
- **保护会延续到失败的 reload 之后。** 重新载入一个受管理的 buffer 会立刻撤下
  插件的写入处理器，但只有在一次读取真正替换掉明文之后才恢复被加固的选项。如果
  那次读取失败，buffer 会保持 `'buftype'` `acwrite` 而背后没有处理器，因此 `:w`
  会以 `E676` 失败，而不是退回 Neovim 自己的写入路径。这不会丢东西：此时 buffer
  已经是空的，因为 Neovim 在读取之前就释放了它的内容。用 `:bd`，或者再成功编辑
  一次该文件（包括重新编辑一个已被删除的文件），buffer 就回到常规状态。
- **不做历史追踪。** 一个被有意保存的明文文件，以后重新打开就是普通文件。没有
  数据库、侧车文件或元数据记录它曾经是 vault，也不承诺保护将来某个无关的 buffer。
- **不产生明文编辑临时文件。** View/Edit 不会把机密交给外部编辑器。密文类操作
  只暂存密文。一次明确的 Decrypt 保存使用原子的明文替换，因此它有意产生的输出
  ——包括这次替换所用的临时暂存文件——可以包含明文。
- **交互式密码不落盘、不缓存。** 一个静态且不含机密的辅助脚本从子进程环境里读取
  密码。密码不会进入 argv、日志消息或文件。如果这个安全辅助脚本不可用，提示输入
  会明确失败；你自己提供的凭据文件仍然可用。交互式密码不会在操作之间保留复用，
  Edit 的保存也一样。
- **安全的错误摘要。** CLI 错误不会包含原始 stdout/stderr、环境变量或完整的命令
  参数，这些都可能含有机密。
- **有守卫的写入。** 操作会检查期间发生的 buffer/文件变化。原子替换保留文件原有
  权限；加密失败或存在冲突的保存不会覆盖源文件，也不会丢弃未保存的编辑。

### 仍然需要你自己注意的部分

插件不会修改全局的 `'shada'`、`'backup'` 或 `'writebackup'` 设置；健康检查会就
相关的持久化风险给出警告。你 yank 进寄存器的内容可能被写入 ShaDa、复制到剪贴板，
或被其他插件使用。备份对不经过插件受管理 buffer 的写入仍然生效。处理机密时，请
自行检查这些设置和其他插件。

明确的明文写出、手工导出、寄存器、其他插件、外部进程以及终端/会话录制都不在这层
保护范围内。明文和密码在使用期间必然存在于进程内存中；插件不承诺擦除内存，也不
承诺防御操作系统 swap、core dump，或另一个能访问该内存或子进程环境的进程。

崩溃泄漏检查会区分「被请求的明文输出」和「非预期的 swap、undo、备份与运行时副本」。
它不是对各种系统级持久化的完备保证。

## 开发

```sh
make test        # 使用假 ansible-vault 的命令驱动测试
make test-real   # 使用 .venv 里真实 ansible-core 的端到端测试（需要 uv）
make test-leak   # 针对非预期明文副本的崩溃检查
make lint        # stylua --check 和 luacheck
make format      # stylua
```

`make test-real` 和 `make test-leak` 首次运行会创建 `.venv` 并安装
`ansible-core`。开发流程与用于生成 release notes 的提交信息规范见
[CONTRIBUTING.md](CONTRIBUTING.md)。

## License

MIT
