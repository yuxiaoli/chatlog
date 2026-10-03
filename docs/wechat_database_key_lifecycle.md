# WeChat 数据库密钥的作用域、生命周期与缓存

## 结论

普通微信数据库的 `DataKey`：

- 通常不会在每次启动、解密或导出时变化；
- 不是整台机器上的所有微信账号共用一把；
- 更适合视为“账号 + 数据目录 + 数据库大版本”对应的可复用主密钥；
- 可以持久缓存，但每次复用前都必须对当前数据库重新验证，不能假设它永久不变。

同一账号数据目录下的普通加密数据库共用一个 32 字节原始
`DataKey`。每个数据库文件还包含自己的 16 字节 salt，解密器使用
`DataKey + salt` 通过 PBKDF2 派生该文件实际使用的加密密钥和 MAC
密钥。因此应缓存原始 `DataKey`，而不是某个数据库的派生密钥。

相关实现：

- 密钥和 salt 长度：[`internal/wechat/decrypt/common/common.go`](../internal/wechat/decrypt/common/common.go#L16)
- Windows v3 派生逻辑：[`internal/wechat/decrypt/windows/v3.go`](../internal/wechat/decrypt/windows/v3.go#L55)
- Windows v4 派生逻辑：[`internal/wechat/decrypt/windows/v4.go`](../internal/wechat/decrypt/windows/v4.go#L54)
- exporter 将同一账号的 `DataKey` 用于普通数据库：[`scripts/export_wechat_history.go`](../scripts/export_wechat_history.go#L1593)

数据库文件和正确的原始密钥复制到另一台机器后仍可解密；解密阶段不依赖
原机器硬件。项目的 Docker 使用方式也要求先在宿主机取得密钥，再交给容器
使用。因此，“机器级永久密钥”不是合适的缓存模型。

## 密钥是否可能变化

代码没有承诺密钥永远不变。重装或重建数据目录、账号迁移、客户端数据库
大版本切换，或者微信主动轮换密钥后，旧缓存都可能失效。

exporter 的处理方式说明项目把缓存密钥视为“可能过期的候选值”：

1. 从中央配置和数据目录配置加载缓存；
2. 选取一个当前加密数据库，用第一页 HMAC 验证候选密钥；
3. 首选密钥失败后继续尝试其他缓存候选；
4. 所有缓存均失败时，才从在线微信进程重新提取。

相关实现：

- 缓存选择与验证：[`scripts/export_wechat_history.go`](../scripts/export_wechat_history.go#L1335)
- 数据库第一页验证：[`scripts/export_wechat_history.go`](../scripts/export_wechat_history.go#L1631)
- 缓存失效后的在线提取：[`scripts/export_wechat_history.go`](../scripts/export_wechat_history.go#L456)

所以正确策略是“持久缓存 + 每次验证 + 失效刷新”，而不是每次都重新提取，
也不是无条件相信一把终身不变的密钥。

## 当前项目的持久化行为

### 主 chatlog 程序

TUI 的“获取密钥”路径会在提取后执行 `Refresh` 和 `UpdateConfig`，把密钥写入：

- 中央配置的账号 `history`；
- 微信数据目录下的 `chatlog.json`。

实现位置：

- 获取并更新配置：[`internal/chatlog/manager.go`](../internal/chatlog/manager.go#L168)
- 从当前微信实例复制密钥：[`internal/chatlog/ctx/context.go`](../internal/chatlog/ctx/context.go#L126)
- 写中央配置和数据目录配置：[`internal/chatlog/ctx/context.go`](../internal/chatlog/ctx/context.go#L251)

独立的 `chatlog key` CLI 路径存在疑似持久化缺陷：它从
`WeChatInstances[i]` 取得密钥后调用 `Context.Refresh()`，但没有先把该实例设为
`Context.Current`；而 `Refresh` 只会从 `Current` 复制密钥。因此命令可以输出
密钥，但新取得的密钥未必被正确写回配置。

### 全量/增量 exporter

exporter 会读取：

- 默认中央配置 `%USERPROFILE%/.chatlog/chatlog.json`；
- 每个微信数据目录下的 `chatlog.json`。

它会合并并验证两处密钥候选。普通的全量或增量导出仍不会把从在线进程提取
的新密钥回写配置；若一个账号此前没有缓存密钥，下次导出仍可能要求微信在线。

staging manifest 和 DuckDB 刻意保持 key-free，不保存数据库或图片密钥：
[`scripts/export_wechat_history.py`](../scripts/export_wechat_history.py#L10)。

### 显式密钥缓存模式

PowerShell exporter 另有一个显式、独立的密钥缓存模式：

```powershell
.\scripts\export_wechat_history.ps1 -SaveKeysOnly
```

`-CacheKeysOnly` 是 `-SaveKeysOnly` 的别名。默认写入
`%USERPROFILE%\.chatlog\chatlog.json`；需要其他中央配置文件时，可同时传入
`-ConfigPath`：

```powershell
.\scripts\export_wechat_history.ps1 -SaveKeysOnly -ConfigPath D:\secure\chatlog.json
```

运行这个模式时必须让微信保持运行。脚本会发现所有当前在线账号，并执行以下
操作：

1. 提取每个账号的普通数据库 `DataKey`，再用该账号当前的代表性数据库重新
   验证它；
2. 对 Windows v4 账号，同时保存能够取得的 `ImgKey`；Windows v3 可能没有
   `ImgKey`，这不算失败；若发现加密的 `BackupFiles/.../Backup.db`，还会从在线
   微信进程提取并用该数据库验证独立的 `BackupFiles` key；
3. 按规范化后的数据目录匹配账号记录，把账号密钥和顶层 `backup_key` 合并写回
   中央 `chatlog.json`，同时保留
   文件中未知的顶层字段、账号字段以及原有账号顺序；
4. 只有所有在线账号都成功提取并验证后才提交更新。任一账号失败时不修改原
   配置；成功时通过同卷的 ACL 受限私有暂存目录和原子替换提交，不创建持久的
   明文密钥备份；
5. PowerShell wrapper 在写入任何临时密钥文件前先保护暂存目录，并把最终文件
   的 Windows ACL 收紧为只允许当前用户、`SYSTEM` 和内置 Administrators 访问。

自定义 `-ConfigPath` 的父目录也必须由上述主体之一拥有，并且不能授予其他主体
写入或删除权限；否则脚本会在提取密钥前拒绝运行，防止暂存目录被替换。

这个模式只缓存密钥并立即退出：它不会创建解密数据库用的 export staging 或
preparation manifest，不会导出或修改 DuckDB，也不会显示“退出微信”的提示。
内部使用的 ACL 受限 key-cache staging 和互斥锁通常会在退出前清理；若清理
失败，脚本会报告仍受 ACL 保护的残留路径。缓存过程中不会把密钥写入 stdout、
日志或 manifest。

`BackupFiles` key 与普通账号密钥是不同的秘密，不会被误写成 `DataKey`。缓存值
使用顶层 `backup_key` 字段；显式传入的 `-BackupKeyFile` 优先于该缓存。

### 无密钥 SQLite 全库备份

需要保留原始 SQLite 数据库结构而不是导入 DuckDB 时，可运行：

```powershell
.\scripts\backup_wechat_databases.ps1 G:\wechat-sqlite-backup
```

该脚本只从指定的中央 `chatlog.json` 读取账号 `DataKey` 和顶层 `backup_key`，
不会读取数据目录内的备用配置。它会先加载并验证缓存密钥；若发现加密的
`BackupFiles/.../Backup.db` 但尚未缓存独立密钥，会在微信仍在线时通过同一套
ACL 受限、原子更新的 `-SaveKeysOnly` 流程恢复并保存它。密钥准备完成后，若
检测到微信仍在运行，再提示用户从菜单或托盘彻底退出。随后脚本递归处理中央
配置中每个账号目录下的所有 `.db` 文件，保留每个账号内的相对路径和完整
SQLite schema/table 数据，并对每个解密结果执行 `PRAGMA integrity_check`。

整个备份采用同卷私有暂存目录，只有所有数据库都成功且源文件清单未变化时才
发布。完整备份的目标目录必须预先不存在。结果包含普通、可直接打开的 SQLite 文件以及
不含密钥和绝对源路径的 `.chatlog-sqlite-backup.json` 清单；中央
`chatlog.json`、`DataKey`、`ImgKey` 和任何密钥值都不会被复制。目标目录虽然
不再需要解密密钥，但消息和联系人内容已经是明文；在 NTFS/ReFS 上，脚本会将
ACL 限制为当前用户、`SYSTEM` 和 Administrators。

已有备份可用 `-Delta` 同步：

```powershell
.\scripts\backup_wechat_databases.ps1 G:\wechat-sqlite-backup -Delta
```

delta 会依据 v2 清单中的源数据库、WAL、快照和文件 SHA-256 证明复用未变化的
SQLite 文件，只重新处理新增或变化的数据库，并从新备份中移除源端已删除的
数据库。它先构造并验证完整的新目录，再通过同卷的旧目录→rollback、新目录→
目标目录两步替换发布；任何可捕获的发布失败都会恢复原备份。旧版 v1 清单缺少
安全复用所需的源指纹，因此第一次 `-Delta` 会明确提示并执行一次完整刷新，把
清单升级为 v2；以后才进行增量复用。

exFAT/FAT32 不支持 Windows 私有 ACL。选择这类目标时，交互式运行会先明确警告
并要求确认；非交互式运行必须显式传入
`-AllowUnprotectedFileSystem`。确认后，最终清单会记录 ACL 不可用，且任何能够
访问该设备的人都可能读取明文历史。应优先使用 NTFS/ReFS；确实需要写入 exFAT
时可运行：

```powershell
.\scripts\backup_wechat_databases.ps1 G:\wechat-sqlite-backup `
    -AllowUnprotectedFileSystem
```

如果不希望使用或更新中央缓存，也可以显式提供独立密钥。显式文件具有最高
优先级：

```powershell
.\scripts\backup_wechat_databases.ps1 G:\wechat-sqlite-backup `
    -BackupKeyFile D:\secure\backupfiles-key.txt
```

该临时输入文件仅用于解密，不会进入目标目录或最终清单，也不会自动覆盖缓存。
若 `Backup.db` 本身已经是普通 SQLite，则不需要该文件。当前缓存格式只有一个
顶层 `backup_key`；如果本机存在使用不同密钥的多个加密手机备份，严格备份会
拒绝生成不完整结果。

## 不同类型的密钥

| 密钥 | 用途 | 是否与普通 `DataKey` 相同 |
| :--- | :--- | :--- |
| `DataKey` | 普通微信 SQLite 数据库 | — |
| `ImgKey` | 微信 v4 图片数据 | 否 |
| `BackupFiles` key | `BackupFiles/.../Backup.db` 和相关备份内容 | 否；缓存为顶层 `backup_key` |

`Backup.db` 被明确排除在普通账号 `DataKey` 流程之外，并使用独立的 backup
key。新的或发生变化的手机备份会优先使用显式 `-BackupKeyFile`，否则使用中央
缓存；缓存缺失时必须让微信保持在线以便恢复。未变化的备份也可以通过已保存的
加密指纹在 delta export 中复用。

## 安全问题

`chatlog.json` 是为项目现有配置格式保留的兼容性缓存，不能视为完整的 secret
storage：

- `data_key`、`img_key` 和顶层 `backup_key` 以明文 JSON 字段保存；
- 主程序写入数据目录下的 `chatlog.json` 时仍使用普通文件权限，Windows 上没有
  显式收紧 ACL；
- TUI 和 Server 配置会在 Info 日志中输出完整 JSON，其中包含密钥；
- Windows 密钥提取器的 Debug 日志会输出完整密钥；
- `chatlog key` 命令按设计把完整密钥输出到 stdout。

相关位置：

- 明文配置字段：[`internal/chatlog/conf/tui.go`](../internal/chatlog/conf/tui.go#L12)
- 数据目录文件写入：[`internal/chatlog/ctx/context.go`](../internal/chatlog/ctx/context.go#L296)
- 完整配置日志：[`internal/chatlog/conf/conf.go`](../internal/chatlog/conf/conf.go#L42)

exporter 不会把密钥写入 DuckDB 或 manifest，并强制使用 Info 日志级别，因此
正常 exporter 路径和 `-SaveKeysOnly` 都不会触发提取器的 Debug 密钥日志。
`-SaveKeysOnly` 只写指定的中央配置，并由 PowerShell wrapper 收紧最终文件的
Windows ACL；但 JSON 内容本身仍是明文，能够以该用户或管理员身份读取文件的
进程仍可取得密钥。不要把该文件同步到不受信任的位置或提交到版本控制。

## 推荐使用方式

建议以以下信息标识一条缓存记录：

```text
account + canonical_data_dir + platform + database_major_version
```

当前 exporter 的推荐流程：

1. 首次缓存或缓存失效时，保持所有目标账号在线并显式运行
   `-SaveKeysOnly`；
2. 让 wrapper 将经过数据库重新验证的 `DataKey` 和可用的 v4 `ImgKey` 原子写入
   ACL 受限的中央配置；
3. 之后运行全量或增量导出。exporter 会在每次使用前重新验证缓存 `DataKey`，
   而不会无条件信任旧值；
4. 若验证失败，再让微信保持运行并重新执行 `-SaveKeysOnly` 刷新全部在线账号；
5. 让 `-SaveKeysOnly` 单独验证 `BackupFiles` key，并以顶层 `backup_key` 保存；
   需要临时覆盖缓存时使用 `-BackupKeyFile`；
6. 永远不要把密钥写入 DuckDB、staging manifest、日志或版本控制。

更高安全级别的后续改进仍包括：

1. 配置与提取器日志的密钥脱敏；
2. 修复 `chatlog key` CLI 的回写路径；
3. 使用 Windows DPAPI、Credential Manager 或其他受保护的 secret storage 代替
   明文 JSON；
4. 保留当前“每次使用前重新验证”的要求，即使未来改用受保护存储也不例外。
