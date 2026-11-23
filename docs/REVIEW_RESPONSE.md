# 审查意见处理记录（2026-11-23）

对照 `REVIEW_REPORT.md`（两位审查者）逐条落地情况。**只做已改动的**，未动的写明原因。
「未处理」表是**第一轮当时**的状态，其中大部分已在第二轮 / 第三轮补掉，见文末。

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

## 第二轮（02:00–02:30）：把"便宜且有用"的继续做掉

| # | 意见 | 处理 |
|---|---|---|
| 13 | AI 闸门缓存 7 天 → 应缩到 6~24h | `GATE_TTL_DAYS = 1`（`ConfigBuilder`） |
| 14 | `allowBackup=false` 挡不住 D2D 迁移 | 新增 `res/xml/data_extraction_rules.xml`，cloud-backup 与 device-transfer 两条通道逐 domain exclude；Manifest 补 `dataExtractionRules` + `fullBackupContent="false"` |
| 15 | VpnService 生命周期缺口 | `setUnderlyingNetworks` + `registerNetworkCallback`（过滤 `NET_CAPABILITY_NOT_VPN`，避免把自己当底层网络）；`onDestroy` 注销；`onRevoke` 明确在 worker 线程拆除；Manifest 补 `stopWithTask="false"`、`foregroundServiceType="specialUse"` + `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` |
| 16 | 32KB × 5 分钟探针流量过高 | 改为 16KB / 600s：8 节点约 18 MB/天（原 73 MB/天），仍能区分 128 与 547 KB/s（125ms vs 29ms） |
| 17 | 用真内核校验配置 | 新增 `phone/tools/check_nodes.py`：把 `nodes.json` 每条 outbound 拼成最小配置跑 `xray run -test -c`；已接进 `build_apk.py` 作为打包前预检（无二进制自动跳过），CI 可设 `XRAY_BIN` 强制执行 |
| 18 | Java 侧零自动化 | CI 新增 `android` job：JDK 17 + Android SDK，取上游 `libv2ray.aar` 的 classes.jar 后 `javac` 全量编译 |

以上遗留四项已在第三轮全部完成，见下节。

## 第三轮（2026-11-23）：剩余四项收口

| # | 意见 | 处理 |
|---|---|---|
| 19 | 真内核校验（TestXray/AAR 导出） | 不导出 AAR：复用 AAR 已暴露的 `Libv2ray.measureOutboundDelay`，把探测 URL 设为故意非法的 `http://[::1`。调用在 `http.NewRequest` 阶段就返回，**不发起任何网络请求**；只把 `config load error` / `instance creation failed` / `startup failed` 判为配置无效。导入订阅时逐条预检（`screenImports`），启动被内核拒绝时后台用 `quarantineInvalidImports` 标记，下次启动跳过；缓存以去除 tag 的 outbound JSON 的 SHA-1 为键，解析规则变化会自动失效 |
| 20 | 投毒语料 + 纯 JVM `parseUri` + CI 闭环 | 新增纯 Java `NodeConfigCodec`（不依赖 Android Framework；自带 Base64/百分号解码器），`ConfigBuilder` 只保留 Context/网络/AAR 胶水。`phone/tests/PoisonHarness.java` 生成 333 条样本（145 接受 / 188 拒绝 / 0 崩溃），`phone/tools/check_poison.py` 编译后把每条被接受的 outbound 和 auto/manual 完整配置交给真 `xray run -test`，并与 `full_config.golden.json` 比对；CI `android` job 固定版本下载 + 缓存后运行。闭环过程中真实修掉 3 条解析规则与内核的漂移（trojan 明文、UUID 长度/格式、`:443` 空主机） |
| 21 | PC `2098` 合并进 TUN 主实例 | `tun_mode.py` 删除 `gai` HTTP outbound / `gai_tag` / 启动前的 `ensure_gai()`；`grp-google`、`grp-amazon`、`grp-dns` 全部由主配置内的 pinned 节点组成，DoH detour 指向 `grp-dns`（IP 字面量探针）。`2098/2099` 保留给分流模式，TUN 停止流程仍会清理残留的 2098 |
| 22 | PC 端「低速假死流」放行 | `watchdog.py` 取两次 Clash API 快照（间隔 4 秒）算实时速率；仅当所有 >20MB 代理流都 ≥60 秒且 <30KB/s，且深测池存在 ≥3 倍速度的备选时放行重建，日志记录「低速假死流放行」；`classify_bulk` / `better_candidate` 有 8 个回归测试 |
| 23 | PC 解析器投毒 + 可移植性 | `nodes.py` 拒绝空主机/空端口/越界端口/空 UUID/空 SS 加密方式；新增 `tests_ci/test_poison_parse.py`（240+ 变异链接，不抛异常、结构可信、危险主机可识别）；`pacroute.py` 的 `winreg` 改为条件导入，非 Windows 可 import |

## 最终验证（2026-11-23）

- `python -m unittest discover -s tests_ci`：**90 tests OK**
- `python phone/tools/check_poison.py`：333 cases / 145 accepted 全部过 `xray run -test`，golden 一致
- `javac -source 8 -target 8`（android.jar + AAR classes.jar）通过
- TUN 配置离线烟雾测试：无 `gai` outbound，DNS 两个 DoH 均 detour `grp-dns`，AI/Amazon 规则指向内建组

## 第四轮（2026-11-23 下午）

| # | 问题 | 处理 |
|---|---|---|
| 24 | `host:port/` 形式的分享链接被整条判为不可用 | `NodeConfigCodec.splitHostPort` 先截掉 authority 后的路径（WS 的 path 在 query 里，不在 authority）；`PoisonHarness` 加定向回归断言（`exit(4)`），不混进语料以免打乱 golden 的 tag 序列 |
| 25 | CI 只做 javac，挡不住 aapt2 / d8 / Manifest 打包期错误 | `android` job 追加「完整打包」步骤：临时 debug keystore + 空节点表 + `PROXY_APK_OUT=/tmp/ci.apk`，断言产物非空。`specialUse` 前台类型、`dataExtractionRules` 这类只在打包时校验的改动从此有 CI 兜底 |
| 26 | Android 15 的 16 KB page size 要求（审查稿 item 16） | 已实测 `libgojni.so`（arm64）三个 PT_LOAD 段 `p_align = 0x4000`，满足要求，无需改构建；此处留记录，将来换 AAR 时按同一方法复验 |

验证：`check_poison.py` 333 cases / 145 accepted 全过 `xray run -test`，golden 未变（定向断言不进语料）。

## 第五轮（2026-11-23 下午，续）

| # | 问题 | 处理 |
|---|---|---|
| 27 | TUN 模式没有自愈：sing-box 被系统收走后 `pcproxy` 网卡消失，用户只看到"网断了" | 新增 `tun_supervisor.py`：随隧道以同一提权进程拉起（DETACHED），每 10 秒检查 `tun.pid`；进程消失且 `TUN_ACTIVE` 仍在时，用 `build_config()` 现算配置、`sing-box check` 通过后重建；10 分钟最多 5 次，超限退避 60 秒。`stop_admin()` 先杀守护再停栈，避免"刚停又被拉起" |
| 28 | 版本与发布 | 升到 **v2.7 / versionCode 9**：`host:port/` 链接不再被判不可用；公版 APK 重建进 `dist/`，`SHA256SUMS.txt` 同步；新增 `.github/workflows/release.yml`，打 tag 即构建并挂资产（需 `PROXY_KEYSTORE_BASE64` / `PROXY_KS_PASS` / `PROXY_KS_ALIAS` / `RELEASE_SIGNING_READY=1`） |

未验证：`tun_supervisor` 只在代码层跑过导入与单测，真实"杀掉隧道再自动重建"需要一次重启才能观察；为避免打断正在使用的网络，本轮没有触发。
