# 代码审查请求（2026-11-23）

两个产物共用同一套节点池与分流策略：

- **PC 便携版**（`pc/`）：Python + sing-box。TUN 接管全局流量，另起 `2098` 端口作为 Google/AI 专用出口。
- **Android App**（`phone/`）：Java + Xray-core。VpnService 建 TUN，内置 8 条节点，支持导入/订阅。

背景：机器在 GFW 环境，节点全部来自免费公开源。目标只有两条——AI 站点能用、大文件不被拖死。
最近为这两条改了 6 个提交，都是线上踩出来的，所以改动密集、局部性强，**需要外部视角判断是否在打补丁而不是修结构**。

---

## P0 正确性：配置生成与启动路径

1. **Xray 配置校验有没有更好的机制**
   现状：内核是「整份配置要么全用、要么全不用」，任意一条出站不合法就 `startLoop` 失败，用户看到的是 `启动失败` + 一长串 core 错误。已在 `ConfigBuilder` 里逐个补：
   - `SUPPORTED_NET`（拒绝 26 已移除的 `http`/`h2`）
   - REALITY 只允许 `raw/tcp/xhttp/grpc`；`xtls-rprx-vision` 只允许 raw
   - SS2022 PSK 必须是 16/32 字节 base64
   想请判断：**是否应该改成"先用 Xray 自己校验一遍"**（例如 `xray -test -c`），或者导入时对每条节点单独起临时实例 `measureOutboundDelay` 探活，不合格的不入池？逐个手写规则显然不可持续。
2. **启动兜底**（`ProxyVpnService.java`）
   `startLoop` 抛错时剔除 `i*` 导入节点、只用内置节点重试一次。请检查：
   - 旧 `controller` 未显式 shutdown，重建是否泄漏 / 是否需要 `Libv2ray` 的显式释放？
   - TUN fd 在失败重试路径上是否正确关闭？
   - 这个兜底会不会掩盖真实错误（比如所有内置节点也坏时，日志是否还能定位）？
3. **PC 端 DNS**
   `tun_mode.py`：`dns.servers = https(1.1.1.1, detour=gai) + local`，`DOMESTIC` 走 local，其余 `final=doh`，53 端口 `hijack-dns`。
   - detour 不能指 `grp-any`（该组 urltest 探针要解析域名，会和 DoH 互相等待，实测导致整机 DNS 超时）。这个耦合还有没有更干净的解？
   - DoH 不可达时是否有降级路径？现在没有，Google 系会直接全挂。
   - 是否该加 DNS 缓存（当前每次查询都过一次 DoH）？
4. **TUN 路由顺序**
   `sniff → Steam → DOMESTIC(direct) → SENSITIVE(direct) → ip_is_private → hijack-dns → reject udp/443 → udp direct → port80 direct → DIRECT/STEAM_DIRECT → GOOGLE_APP → AMAZON → GENERAL → geoip-cn → final`。
   请确认：`reject udp/443` 会不会误伤正常 QUIC 应用（比如某些 P2P / 视频）；`port 53` 与 `hijack-dns` 的先后是否还有边界情况。

## P0 安全

5. **凭据处理**：`gen_nodes.py` 只打印 address/port（vmess 的 base64 整串是凭据，不能 echo）；`_账号信息` 是明文文件。请检查日志、异常栈、UI 里有没有把 UUID/密码带出去的地方。
6. **订阅导入**：`SubscriptionGuard` 拦本地地址（防 SSRF）。请检查重定向、IPv6 link-local、DNS rebinding、响应体大小上限。
7. **APK 签名与备份**：keystore 在仓库里（`phone/phoneproxy.keystore`），密码走环境变量。`allowBackup` 是否会把导入的节点一起备份出去？这是明文凭据。
8. **TLS 到代理本身**：`https://` 分享链接被直接拒绝（Xray http 出站没有客户端 TLS，会把代理密码明文发出去）。请确认这个取舍是否还成立。

## P1 可靠性 / 移动端

9. **VpnService 生命周期**：网络切换（Wi-Fi ↔ 蜂窝）、`onRevoke`、Always-on VPN、开机自启、进程被杀后重建——现在哪些路径没处理？
10. **IPv6**：TUN 同时接管 v4/v6 是刻意的（否则 v6 泄漏真实 IP）。请检查 DNS 的 `queryStrategy: UseIPv4` 与 v6 路由是否一致，以及 Xray 出站对 v6-only 目标的表现。
11. **节点选择的度量**：PC 用 `node_deep.json` 的 `dl_kbps` 排序；手机探针改成 32KB 负载（`speed.cloudflare.com/__down`）。请判断：
    - 32KB × N 节点 × 5 分钟的移动流量成本是否可接受（当前 8~128 节点）；
    - 有没有更省的方案（比如只在 Wi-Fi 下探、或用历史吞吐加权/success rate 而不是单次延迟）。
12. **单点失败**：PC 端 `gai`(2098) 是二级出口，一个 sing-box 实例。它挂了 AI 域名全挂（有看门狗脚本但 TUN 模式下未启用）。是否该合并进主实例，用 selector 实现？

## P1 构建 / 测试 / CI

13. **CI 只跑 Python 单测**（`tests_ci`，78 个，覆盖 PAC）。Java 侧完全没有自动化：建议至少加一个 `javac` 编译检查（需要 android.jar），或用 Gradle 替代自研 `build_apk.py`？
14. **缺测试的地方**：URI 解析（`parseUri` 的边界：畸形 base64、缺字段、异常端口、超长字段）、`ConfigBuilder.fullConfig` 的输出结构（golden test）、`tun_mode.build_config`（同样可 golden）。
15. **建议加一个"投毒"测试**：喂 200 条随机/畸形分享链接，断言不抛异常、且每条被接受的结果都能通过协议校验——这正是连续三次线上事故的共同点。
16. **版本与产物体积**：APK 56.9 MB（内嵌 libvray + 8 节点），`versionCode` 目前怎么递增？16KB page size 对齐（Android 15 要求）有没有做？
17. **Python 侧**：没有 lint/format（ruff/flake8），没有 `pyproject.toml` 锁定依赖，`runtime/python` 是打包进去的解释器。

## P2 可维护性 / 体验

18. **错误信息**：现在直接把 core 的报错原文抛给用户（`infra/conf/serial: ...`），是否该映射成"第 N 条节点不合法，已跳过"并把详情放日志？`lastSkips` 已有数据，但没在 UI 呈现。
19. **导入体验**：公开源 120 条里大量死节点/不合法节点，是否该默认关闭公开源导入、只保留订阅导入？
20. **PC 端进程模型**：提权子进程依赖父控制台存活（作业对象），用户关窗就断网。是否该改成计划任务/服务？`DETACHED_PROCESS` 试过，作业不允许 breakaway。
21. **文档一致性**：`安装说明`、`使用说明.txt`、`README` 三处的端口表/行为描述是否同步？`2098/2099/19091` 的职责有没有写清。

## 已知问题（不必重复指出）

- 免费节点质量：上行 0.1~0.5 MB/s，十几分钟就能掉一半；配置层已到顶。
- 手机端「测速」按钮只测延迟不测吞吐。
- Google 账号地区 / 学生认证那条线未完成（缺美国付款资料与卡）。

## 怎么跑

- 单测：`python -m unittest discover -s tests_ci`
- PC：`cd pc/_proxy && python tun_mode.py start`（管理员，建 `pcproxy` 网卡）；诊断 `python doctor.py`
- APK：`cd phone && python build_apk.py`（JDK 17 + Android SDK build-tools，不依赖 Gradle）

## 环境事实

Windows 11、中文路径、GFW 环境、免费节点。PC 端 `pcproxy` + `2098` 二级出口是刻意设计：Google 对 gemini/antigravity 有独立地区判定，必须单独挑出口。
