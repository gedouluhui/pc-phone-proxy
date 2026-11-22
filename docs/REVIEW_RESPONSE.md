# 审查意见处理记录（2026-11-23）

对照 `REVIEW_REPORT.md`（两位审查者）逐条落地情况。**只做已改动的**，未动的写明原因。

## 已修复

| # | 意见 | 处理 |
|---|---|---|
| 1 | `ProxyVpnService` 重试前不释放旧 controller | 新增 `newController()`；重试前 `stopLoop()` 并置空，避免 Go 侧状态残留 |
| 2 | 失败后复用 `tunFd` 可能拿到已关闭的 fd（EBADF） | 改为 `closeTun()` 后重新 `buildTun()`（`Builder` 抽成方法），不再复用旧 fd |
| 3 | 兜底用 `tag.startsWith("i")` 判断内置节点 | 改用 `Node.imported` 字段（公版 APK 空内置时不再误判） |
| 4 | 兜底后 `nodes`/`selection` 没同步，UI 显示与实际路由不一致 | 重试时 `nodes = builtin`，选中的导入节点被剔除则回落 `"auto"` |
| 5 | 首次 `startError` 被吞 | 先 `Log.e` + `log()` 输出真实错误，再走兜底 |
| 6 | `SubscriptionGuard` 字符串检查挡不住 DNS rebinding | 新增 `checkResolved()`：`getAllByName` 逐 IP 检查回环/私网/链路本地/多播/ULA/CGNAT/IPv4-mapped，在连接前调用 |
| 7 | 订阅重定向：相对 Location 会误判、允许 https→http | `target.resolve(location)` + 禁止降级 |
| 8 | 订阅流未在 finally 关闭 | `in.close()`/`disconnect()` 进 finally；上限 10 MB → 2 MB |
| 9 | 节点地址未过滤私网（Android 端可被当内网扫描器） | `parseUri` 对字面量地址过 `SubscriptionGuard.checkHost`，私网/回环直接跳过 |
| 10 | 无条件采纳 `allowInsecure=1` | 导入节点入库前 `stripAllowInsecure()` 强制 false（内置节点不受影响） |
| 11 | PC TUN 未接管 IPv6（v6 流量与 v6 DNS 绕过隧道泄漏） | `address` 增加 `fdfe:dcba:9876::1/126`，与手机端对齐 |
| 12 | DoH 硬绑 2098 单进程，且退化时是单节点 | 新增 `grp-dns` urltest，探针为 **IP 字面量** `https://1.1.1.1/cdn-cgi/trace`（探针不需要 DNS，从拓扑上消除死锁），DoH 的 detour 指向它；再补一组 `8.8.8.8` DoH 做互备 |

## 未处理（附原因）

| 意见 | 原因 |
|---|---|
| 用 `xray -test -c` / `TestXray` 做内核级 Dry-Run | 需要改 Go AAR（AndroidLibXrayLite 只暴露 `StartLoop`/`measureOutboundDelay`），属于构建链改动，要单独排期；当前先用「解析期强校验 + 启动失败上报真实错误」兜住 |
| CI 接入 Java 编译 + JUnit + 真内核投毒测试 | 需要 GitHub Actions 装 JDK 17/Android SDK 并下载 xray 二进制，工作量大；本次先把校验规则固化，CI 另开 PR |
| 32KB 探针成本（8~128 节点 × 5 分钟） | 已确认 observatory 的周期是 300s 且只有一层，没有叠加 30s 巡检；按 8 节点算约 0.7~2.4 GB/月，仍偏高，但降到 204 会退回「按延迟选节点」的老问题。建议按审查者方案改成「Top N + 灭屏/计费网络降频」，需要改 Java 侧调度，未在本轮做 |
| `onRevoke` / `NetworkCallback` / `setUnderlyingNetworks` / `stopWithTask` | 都是 `ProxyVpnService` 的生命周期补强，改动面比本轮大，留作下一批 |
| VpnService 的 `specialUse` 前台服务类型 / POST_NOTIFICATIONS | 需同时改 Manifest 与 targetSdk 验证，单独做 |
| keystore 移出仓库 | 已确认 `*.keystore` 在 `.gitignore` 里、仓库内没有该文件（审查者也核实了），无需处理 |
| `allowBackup` 的 D2D 通道 | 当前 Manifest 是 `allowBackup="false"`；补 `dataExtractionRules` 需新增 xml 资源，未做 |
| PC 端 `2098` 合并进主实例 | 本轮用 `grp-dns` 消除了 DoH 对 2098 的依赖；`grp-google`/`grp-amazon` 仍用 `gai`，合并属于更大重构 |
| AI 闸门缓存 7 天 → 24h | 未找到具体实现位置（`deep_test.py`/`start_proxy.py` 内），下一轮定位后改 |

## 验证

- `sing-box check` 通过（15 条路由规则，双栈地址，`grp-dns` 探针为 IP 字面量）
- `build_apk.py` 通过（内嵌 8 节点）
- **PC 端配置需要重启一次「启动代理」才生效**（TUN 需要管理员重建网卡）
