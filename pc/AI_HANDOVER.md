# 代理便携版 V3.2.1 —— 交接说明

给下一个接手的人（或 AI）。**先读「当前必读」，再动手改代码。**

---

## ✅ 2026-11-23 19:50 当前状态（V3.2.1，main 已推送、CI 全绿、便携版已部署）

- **断网根因已修**：TUN 路由不再有 `process_name` 直连规则（`stack=system` 下所有连接在 Windows 上都归属
  sing-box 自己，等于全局直连；17:34、18:13 两次断网都是它）。`tests_ci` 断言该规则不得再出现。
- **测速进程自己绕开 TUN**：`nodes.bypass_route()` 给深测 / 闸门 / 预筛的临时 sing-box 加 `auto_detect_interface`
  （或自检选出的 `default_interface`）。`tun_supervisor.bypass_selftest()` 实测「被墙地址连通 < 2 个、国内对照能连」
  才算通过，结论写 `logs/bypass_mode.json`（6 小时有效）；不通过就不重扫。手动自检：放 `_proxy/SELFTEST_REQUEST`。
- **换池不得变差**：`switch_min_live(当前隧道上次闸门能连上数)` = max(2, min(当前, 3))；新池不够就拒绝切换并恢复
  `singbox_pinned.good.json`。
- **重建后外网自检 + 自动回滚**：`restart()` 用 `.new` 启动，然后经隧道对 google / github / cloudflare 做 TLS 握手
  （最多 3 轮）。境外全断、国内能通 → 杀掉新进程、用原配置重新拉起（坏配置存 `singbox_tun.json.broken`）；
  国内也不通 → 判为本机断网、不动；新配置 2 秒内退出 → 立刻用原配置拉回。成功前磁盘上的 `singbox_tun.json` 一直是旧的。
- **实机验证（19:33–19:50）**：自检通过（mode=auto）；重扫时测速路径未被转发（被墙 1/3）；8993 个候选里真实直连可达 15 个
  （之前那批「全是 1.8~2 MB/s」的结果是被隧道转发的假数据）；新池闸门 3 个能连上（= 当前隧道，门槛 3，放行）；
  19:50:18 切换，外网自检通过，19:50:41 新隧道就绪，整个过程断流约 20 秒、自动恢复。切换后 Google 判定地区 US，
  Gemini / AI Studio / ChatGPT / GitHub 均可打开，无「地区不可用」。
- 自动重扫已恢复（每 15 分钟闸门；能连上 < 3 或节点池超过 24 小时 → 重扫，3 小时最多一次）。
- **仍未做**：手机端真机验收；免费节点真实可达数偏少（当前 3 个能上 Google 的出口），需要更多大陆可直连的源。


## ⚠️ 2026-11-23 18:10 必读：17:34～18:02 整机外网中断事故（另一个会话留言）

**现象**：17:34 起 TUN 换上新节点池后外网全断（Google/GitHub/ChatGPT 全部超时，只有国内站能开），
`tun_supervisor` 每 1~3 分钟因「DNS 解析失败」换 DoH 出口重建一次隧道，持续约 30 分钟。

**根因链**（日志已核对）：
1. 17:09 `maintain()` 判定「隧道没有直连规则」→ `restart()`；`restart()` **先把新配置改名成 singbox_tun.json 再启动**，
   新进程立刻退出（旧隧道还占着网卡），但磁盘上的配置已是新的；
2. 17:10 下一轮 `running_has_direct_rule()` 读的是**磁盘文件**而不是正在跑的进程 → 误判已有规则 → 在旧隧道下开始重扫；
3. 深测子进程被旧隧道二次转发，`node_deep.json` 里一片 1.8~2.0 MB/s（与 05:11 那批污染数据同一特征）；
4. 17:32/17:34 `REBUILD_REQUEST`：闸门已经测出新池 **30 个出口全部 err**，旧逻辑仍「继续重建」→ 断网。

**已做的现场恢复**（只动了便携版运行数据，没停过任何进程）：
- `_proxy/singbox_pinned.json` 换回事故前的 10 个出口（URI 从 `raw/` 里按 server:port 找回），写 `REBUILD_REQUEST` 让守护重建；
  18:02 起恢复，18:07 闸门 8/10 可用；Google/ChatGPT/Gemini/YouTube 实测可开。
- `_proxy/tun_mode.py` 暂时回退为 `_bak_20261123b`（14:20 版，跑了 3 小时没问题的那份；**不含 process_name 直连规则**）。
- `_proxy/rescan.lock` 暂停自动重扫约 2 小时（到 19:55）。事故现场备份在 `_proxy/_bak_20261123e/`
  （`singbox_pinned_newpool.json` 就是那份 30 个全死的池）。

**已写进仓库工作区、尚未提交/推送的修复**（请接手的会话一并提交并跑 CI，再部署）：
- `pc/_proxy/tun_supervisor.py`：`pool_switch_ok()`——新池切换前闸门能连上（ok/bad）的不足 2 个就拒绝切换，
  并用 `singbox_pinned.good.json` 恢复上一份可用池；健康时 `save_good_pinned()` 自动存这份备份；
  `restart()` 改为用 `.new` 启动、进程活下来才改名（磁盘配置不再先于进程变化）。
- `pc/_proxy/rescan.py`：TUN 开着时先用测速同款的直连 SOCKS 探 3 个被墙地址（Google/Facebook 443），
  ≥2 个能连上 = 测速路径被转发 → 本轮不扫、节点池不动（`canary_contaminated()`）。
- `tests_ci/test_tun_safety.py`：上面两处的单测。

### 18:20 更新：根因确认 = `process_name: sing-box.exe → direct` 这条规则本身（不是只有节点池的问题）

- 18:06 另一个会话把带这条规则的 `tun_mode.py`（仓库同款，sha1 前缀 c4653d50）重新部署进便携版；18:13 守护按它重建后
  **外网再次全断**（节点池仍是那 10 个好节点，闸门 9/10 ok）。18:17 再换回 `_bak_20261123b/tun_mode.py`、18:18 重建，
  18:19 实测 Google 2.6s / ChatGPT 2.3s / Gemini 2.1s / GitHub 4.1s 全部恢复。
- 对照：所有带这条规则的隧道（17:34–18:02、18:13–18:18）都断网；所有不带的（14:23–17:34、18:02–18:13、18:18 起）都正常。
  17:09 第一次尝试带规则重建就「立即退出」，这条规则在 17:34 之前**从没真正跑起来过**。
- 推断原因：`stack: system` 下 TUN 的 TCP 连接会被 sing-box 自己的本地监听接住，Windows 上按连接查进程得到的是
  **sing-box.exe 本身**，于是所有流量命中 `process_name: sing-box.exe → direct`，等于全局直连（国内站能开、外网全超时）。
- **正确做法**（尚未实现）：删掉这条规则；让深测/闸门/预筛用的临时 sing-box 自己绕开 TUN——在这些临时配置的
  `route` 里加 `"auto_detect_interface": true`（或对出站设 `bind_interface` 为物理网卡），与主实例相同。
  改完必须在 TUN 开着的情况下实测「被墙地址直连不通 + 主隧道外网正常」两件事，再部署。
- 便携版现状：`tun_mode.py` = 14:20 版（无该规则）；`DO_NOT_DEPLOY_TUN_MODE.txt` 写明原因；自动重扫已暂停到 **11-24 18:2x**（做法：`logs/pool_health.json` 的 `last_rescan` 写成未来时间，附 `paused_note`；`rescan.lock` 不可靠——它挂的守护进程 18:05 已退出）。手动放 `RESCAN_REQUEST` 仍会绕过暂停，规则修好前别放；
  `tun_supervisor.py` / `rescan.py` 仍是另一个会话 17:27 的版本，我的防护修复只在仓库工作区。
- 已知副作用：Google 地区闸门每次判出 bad 节点都会重建隧道（18:07、18:13 各一次），每次断流数秒。
- 仓库 `pc/_proxy/tun_mode.py` 与 GitHub main（v3.2，`21911fe`）都还带着这条规则，**未修**。
- 18:22 出现约 1 分钟的外网超时，期间没有重建、配置不带该规则，18:24 自行恢复（Google 2.6s / ChatGPT 4.7s / GitHub 2.2s / YouTube 3.9s）：属免费节点抖动、urltest 切换，不是新事故。
- 18:17 另一个会话又把 `tun_supervisor.py` 部署进了便携版（sha1 前缀 7bffa731），说明它仍在工作；接手前先确认只剩一个会话在改电脑端。

- **「另一个会话」是谁**（18:26 查清）：不是别的程序，是**这同一个对话的分支**。16:19 和 16:21 用户发的「电脑端和手机端都改进到最好」各自开了一个分支；分支 `branch-b22efb63`（16:21 起）一直在改电脑端，用户在里面问过 Gemini 打不开（16:55、17:18）、18:15 回复「你继续就行，由你负责」，18:25 仍在活动。主线（本节作者）同时在做事故恢复。两边改的是同一批文件，所以才互相覆盖。另一个独立对话「Kaggle比赛全权接手与金牌冲击」只做比赛，不碰代理文件。**以后只在一个分支里改电脑端。**
**请不要两个会话同时改 PC 端**：本次事故就是在一边部署、一边自动重扫的时候发生的。


## 一、当前必读（2026-11-20 这一轮）

用户报「节点很多失效、TUN 一接管就没网、AI Studio 打不开、驱动下载不了」。
实机排查出五个根因，全部已修并推送：

1. **幽灵 TUN**：旧目录启动的提权 sing-box 不带本目录标记，关闭流程看不见它，
   它继续占着 `pcproxy` 网卡和控制端口，表现为「所有节点都像死了」。
   → `tun_mode.foreign_tun_pids()` 按网卡/控制端口/空命令行三重特征识别；
   分流模式启动前也会先关 TUN。
2. **控制端口撞车**：原来用公共 9090，被 Clash 系工具或旧副本占用时出口
   `bind` 失败 FATAL，日志却像节点全挂。→ 分流改 19090，TUN 改 19091。
3. **fast 组只有 1 个成员**：单节点抖动整条 2103 断。→ 不足 3 个时放宽阈值补齐。
4. **驱动下载被送进节点**：厂商按出口 IP 分配 CDN，走节点拿到境外源，几百 MB
   必断；Windows Update 过代理还会破坏 BITS。→ `DRIVER_DIRECT` 全部改直连。
5. **PAC 地址是固定 URL**：浏览器缓存旧表，补的规则永远不生效（命令行 200、
   浏览器打不开）。→ URL 加内容哈希 `?v=<sha1前8位>`。

另外新增两件事：

- **直连优先**：内置 `rulesets/geoip-cn.srs`，目标 IP 在中国境内一律直连。
  域名列表只负责需要提前分流的站点。Steam / 壁纸引擎在直连判定之前显式走代理。
- **Google AI 专用出口**：Google 按出口 IP 判定地区，同一批节点里有的被
  拒（notebooklm 返回 `location=unsupported`）。分流模式仍由 `start_proxy.py`
  在 `2098` 上用 `pinned.json` 里除 `google_bad.json` 之外的节点组成 urltest 组；
  **TUN 已不再依赖它**：`tun_mode.build_config()` 在主实例里直接建 `grp-google`
  （同样的过滤 + Gemini 探针）、`grp-amazon`（AWS 探针）和 `grp-dns`
  （`1.1.1.1` IP 字面量探针），DoH 的 detour 指向 `grp-dns`。

提交：`0035ed5` → `48e0bc3` → `7b9161c` → `fc43f9c` → `954272c`。

### 2026-11-23 17:00：Gemini / AI Studio 打不开（出口池耗尽）+ TUN 自动重扫

- 现场：TUN 10 个出口只剩 g2/g4 能上 Gemini（g0 超时，7 个全死）。节点池来自 05:11 那次在 TUN 下被二次转发
  污染的深测；**TUN 模式没有看门狗，节点池从不自动刷新**；DoH 出口被钉在单节点 g2。g2 一抖 Google 就打不开。
- `tun_supervisor.maintain()`（计划任务每分钟，隧道健在时才跑，异常只记日志）：每 15 分钟经 clash API
  （127.0.0.1:19091）实测能上 `gemini.google.com/robots.txt` 的出口数，写 `logs/pool_health.json`；
  `< 3` 个或 `node_deep.json` 超过 24 小时 → 自动重扫（3 小时最多一次，`rescan.lock` 防重入，日志
  `logs/rescan_auto.log`）。当前隧道配置没有「测速进程直连」规则时先重建一次再扫。
  也可手动放 `_proxy/RESCAN_REQUEST`（立即重扫）或 `_proxy/REBUILD_REQUEST`（按新池重建）。
- `rescan.py`：TUN 开着时扫完写 `REBUILD_REQUEST`，1 分钟内自动换新节点（先 `sing-box check`，坏配置不生效）。
- `rotate_dns_detour`：只在实测能到 1.1.1.1 的节点里挑。`restart()`：计划任务与常驻守护同时重建时，
  对方先成功则视为成功（17:09 实测撞车过一次，隧道本身没问题）。
- `nodes.tcp_prefilter`：TUN 开着时经「只有 direct 出站的 sing-box SOCKS（127.0.0.1:29099）」预筛。
- `tun_mode`：`GOOGLE_DNS` 域名的 80 端口走 `grp-any`（以前直连必超时）。
- 17:09 已在用户机器上自动重建（pid 100932，新配置含直连规则），17:10 自动开始重扫。
- 回滚：`代理便携版/_proxy/_bak_20261123c/`（v3.2 版）或 `_bak_20261123b/`（原版），`rollback_pc_update_20261123.bat`。

### 2026-11-23 傍晚：Hysteria2 / 新源 / 隧道重建不再断网

- `nodes.py`：新增 `parse_hysteria2`（`hysteria2://` / `hy2://` → sing-box `hysteria2` 出站，含 salamander、
  端口跳跃 `server_ports`、`insecure=1`），`tcp_prefilter` 对 UDP 节点直接放行交给 sing-box 实测。
  公开源里每天约 300 条 hysteria2，以前全部被当成「无法解析」丢掉。
- `harvest.py`：新增 6 个在本机网络实测存在的源（tony163 / Barabama clashmeta / free18 / aiboboxx sub /
  barry Sub1 / chengaopan）。
- `tun_mode.start_admin`：**先生成并 `sing-box check` 新配置，通过才停旧隧道**；以前先停再建，新配置一坏就断网。
- `tun_supervisor.restart`：先生成+校验新配置再停旧进程；新配置不过就回退到上一份能用的 `singbox_tun.json`。
- `tun_mode.build_config`：路由第一条 `process_name: sing-box.exe/xray.exe → direct`（TUN 开着扫描也测真实直连结果）。
- CI：`tests_ci/test_singbox_configs.py` 用与便携版同版本的真 sing-box 1.14.4 校验 TUN / 深测 / 延迟测三套
  生成配置（含 Hysteria2），任何生成器把配置写坏都会在 CI 失败，而不是在用户机器上重建时断网。
- 部署：CI 通过后才复制进 `代理便携版/_proxy`（覆盖前备份到 `_proxy/_bak_20261123b/`，回滚见
  `kaggle/PHONEPROXY_V3_HANDOVER_2026-11-23.md`）。正在运行的隧道进程不受影响，新代码在下次重建/扫描时生效。

### 2026-11-23 下午：TUN 开着扫描会测出假结果（手机端全灭的根因之一）

- 手机端 24 个内置节点、144 个节点池全部不可用。查 `logs/tun.log`：TUN 从 04:46:56 一直接管，
  `node_deep.json` 05:11 生成——深测用的 sing-box 子进程被 TUN 接管、经当前出口二次转发，测的是「节点套节点」。
  harvest 的 TCP 预筛在 system stack 下对任何 IP 都能连上，也失效。
- 修：`tun_mode.build_config()` 路由第一条 `{"process_name": ["sing-box.exe", "xray.exe"], "outbound": "direct"}`。
  主实例出站走 `auto_detect_interface`，不受影响。仓库与 `代理便携版/_proxy` 两份已同步，**下次启动 TUN 生效**。
- 之后要重新扫描节点 → `phone/gen_pool.py` → `phone/build_apk.py`，内置池才是真实大陆直连可用的。
- 手机端同时改为 v3.0（本机实测选线、节点池自维护），详见 `phone/README.md` 与
  `kaggle/PHONEPROXY_V3_HANDOVER_2026-11-23.md`。原文件备份在 `kaggle/_bak_phoneproxy_20261123/`。

### 2026-11-23 这一轮

- `tun_mode.py` 删除了 `gai` HTTP outbound、`gai_tag` 和启动前的 `ensure_gai()`；
  AI/Amazon 组直接使用主实例内的 pinned 节点。`tun_mode.py gai` 子命令一并删除，
  `修复AI出口.bat` 只对分流模式有意义。
- `watchdog.bulk_active()` 改为两次快照（间隔 4 秒）算实时速率；低速僵尸流
  在存在 3 倍以上深测备选时放行重建；`classify_bulk()` / `better_candidate()`
  有 `tests_ci/test_zombie_release.py` 覆盖。
- `nodes.py` 拒绝空主机/空端口/越界端口/空 UUID/空 SS 加密方式；
  `tests_ci/test_poison_parse.py` 覆盖 240+ 变异链接。
- `pacroute.py` 的 `winreg` 改条件导入，非 Windows 可 import。

---

## 二、入口与目录

```
代理便携版\
  启动代理.bat      选择模式并启动（1 分流 / 2 TUN）
  关闭代理.bat      完整关闭：进程、PAC、静态代理、环境变量、直连实测
  体检.bat          六层体检，第一个 FAIL 就是根因
  修复AI出口.bat    只重建分流模式的 2098，不动隧道（TUN 模式不需要）
  重新扫描节点.bat  重抓公开源 + 深测（10-40 分钟）
  命令行代理.bat    给 Codex/git/pip 用的终端（2090）
  查看代理报告.bat  打开 report.html
  runtime\          内嵌 CPython（不依赖系统 Python）
  _proxy\           全部代码与运行时数据
```

`_proxy` 里的关键文件：`start_proxy.py`（编排）、`bestroute.py`（选线+生成配置）、
`pacroute.py`（PAC 渲染/安装）、`tun_mode.py`（TUN 生命周期）、`watchdog.py`
（自愈）、`doctor.py`（体检）、`pinned.json`（当前出口组成员）、
`node_deep.json`（深测快照）、`google_bad.json`（被 Google 拒的节点）。

---

## 三、端口表

| 端口 | 用途 |
|---|---|
| 2101 | general 组（ChatGPT / Claude / OpenAI） |
| 2103 | fast 组（网页 / GitHub / HF / Google AI 回退） |
| 2090 | 命令行混合入口（静态兜底，按域名分流） |
| 2086 | 香港单节点（Reddit；深测池无 HK 时不存在） |
| 2096 | Steam 美国单节点 |
| 2098 / 2099 | Google AI 专用出口（**仅分流模式**；TUN 已内建同一组，不启动它） |
| 19090 / 19091 | 分流 / TUN 的 clash 控制端口（只绑 127.0.0.1） |
| 8891 | PAC 服务（`/proxy.pac?v=<hash>`） |

---

## 四、分流策略（直连优先）

1. 显式规则（按顺序）：Google AI → grp-google；AI 站 → grp-general；
   `DIRECT`（含驱动/Windows Update/Steam 下载 CDN）→ 直连；
   `STEAM`（商店/创意工坊）→ 代理；国内/银行/支付/政务 → 直连。
2. **兜底**：`geoip-cn` 规则集命中 → 直连。
3. 其余 → urltest 组。

命令行入口（2090）用同一套规则，另外把 Kaggle 固定直连。

---

## 五、故障处理顺序

1. 双击 `体检.bat`，按行序看第一个 FAIL。
2. 出口端口红 → 重跑 `启动代理.bat`（会重建出口组）。
3. PAC 红 → 重跑 `启动代理.bat`；浏览器要**完全退出**才会重读 PAC。
4. AI 站点打不开 → 分流模式点 `修复AI出口.bat`（只换 2098，不断网）；
   TUN 模式在 `tun-mode.bat` 里重建隧道即可，AI 组会随主配置一起换节点。
5. 节点普遍不行 → `重新扫描节点.bat`；看门狗平时每 12 小时自动做一次。
6. TUN 启动报「UAC 未确认」→ 看任务栏盾牌图标；报「已在运行」会自动重建。

日志：`_proxy\logs\`（`tun.log` 是 TUN 进度，`tun_singbox.log` 是 sing-box
自身错误，`watchdog.log` 是自愈记录，`doctor.json` 是体检结果）。

---

## 六、已知限制（别当 bug 反复查）

- 免费公开节点寿命几天到几周，失效是常态；机制只能做到「1 分钟切走、12 小时补新」。
- Reddit 在多数机房 IP 上 403；深测池经常没有香港节点。
- Google AI 的资格按**账号地区**判定，换节点无效（Antigravity 尤其明显）。
- 免费节点存在 TLS 中间人，不要用它们登录银行/政务；相关域名已强制直连。
- `node_deep.json` 里旧的 URI 可能是 300 字符截断值，需要重跑 `deep_test.py`。

## 2026-11-21 接手后的第一轮修改（DNS 污染 / Gemini 打不开 / 慢）

用户报「AI Studio 慢、Gemini 打不开」，实测定位到三件事，已改并验证：

1. **DNS 污染**（根因）。系统解析对 `gemini.google.com` 返回 Facebook 的
   `31.13.x` / `2a03:2880::`，`chatgpt.com` 返回 `157.240.0.35`，
   `huggingface.co` 返回 `103.252.115.53`。浏览器拿着假 IP 连，TLS 必然挂
   （表现为 SSL EOF / 证书主机名不匹配）。TUN 现在自己解析：
   `dns.servers` 加 `doh`（1.1.1.1, detour=grp-any）+ `local`；
   `DOMESTIC` 走 local，其余 final=doh；规则里 `{"protocol":"dns","action":"hijack-dns"}`。
   改完 `nslookup gemini.google.com` 返回 142.251.15x.2。
2. **Google 组按延迟挑节点 = 挑到最慢的**。实测同一批节点 1MB 下载
   389 / 122 / 75 / 43 / 33 / 6 / 5 KB/s，而 urltest 只看延迟，选中 33 KB/s 那颗。
   现在 `grp-google` 的探针改成 `https://gemini.google.com/robots.txt`
   （gstatic 谁都能过，但 Gemini 有独立地区判定），成员按 `GOOGLE_PREFER`
   实测吞吐排序，`gai` 放末尾兜底。
3. **TUN MTU 1500 → 1400**，并补 `route.default_domain_resolver: local`
   （sing-box 1.14 起不加会 FATAL）。

顺带修掉一个真 bug：`stop_proxy.stop_tun()` 调 `tun_mode.py stop` 时没带
`--admin/--result`，会把 `tun_result.json` 覆盖成「TUN 已停止」，导致
「启动代理」的等待方提前退出、建到一半的隧道没人等（现象：点启动只看到停止）。
现在 stop 写自己的 `logs/tun_stop_result.json`。

改动文件：`tun_mode.py`、`stop_proxy.py`、`google_bad.json`（加了
`subgift.gcorecdn.com`、`51.161.204.244`）、`singbox_tun.json`（生成物）。
原文件备份在 `_proxy/_bak_20261121/`，回滚＝覆盖回去再点一次「启动代理」。

验证：`doctor.py` 从 4/7 → **7/7 站点直通**（ChatGPT 1.6s / Gemini 3.9s /
AI Studio 2.6s / GitHub 1.6s / HuggingFace 1.8s）。

**仍未解决**：免费节点带宽抖动（同一颗节点 10 分钟内能从 389 KB/s 掉到
41 KB/s），大页面还是会转圈；要稳只能换付费/住宅出口。另外 `出口身份` 那行
仍显示 CN IP，是探针域名被归到直连规则，不影响上面 7 个站的实测结论。

**运行期注意（11:52 补）**：TUN 是提权进程，会被拉起它的控制台所在作业带走。
用脚本/AI 会话拉起时，会话结束隧道就消失（表现为突然全断）。要么由用户
双击 `启动代理.bat`（它自己的窗口，最稳），要么让拉起方一直保活。
`synchronize` 之外别用 `Start-Process -Verb RunAs` 起 sing-box，安全策略会拦。

## 12:00–12:15 第二轮：上传和大页面慢

用户反馈：20MB 传 AI Studio 传不上去，ChatGPT/Claude 一直转圈。又找到两个真问题：

1. **QUIC 被直连黑洞**（影响最大）。旧规则 `{"network":"udp","outbound":"direct"}`
   把 QUIC(UDP/443) 丢给直连，国内这方向是不通的；浏览器先发 QUIC、等超时才
   回落 TCP，页面就一直转。加 `{"network":"udp","port":443,"action":"reject"}`
   让它立刻回落 —— **ChatGPT 首页从 20s+ 降到 3.2s**，Gemini 从"超时"到能整页加载。
2. **gvisor 用户态栈拖吞吐**。同节点实测：直连 547 KB/s，经 gvisor 236 KB/s。
   改 `"stack": "system"`（内核 TCP）。回滚改回 gvisor 即可。

另外把分组从"10 颗按延迟选"收成**实测吞吐前 4 颗**（g9/g6/g8/g7），因为
urltest 会选中延迟 4004ms 的慢节点；grp-google 继续保持 gai 末尾兜底。

实测（12:13）：10MB 上传 **31.7s / 316 KB/s**（20MB 约 1 分钟）；
ChatGPT 3.2s、AI Studio 1.9s、Gemini 7–16s（节点下行抖）。

**Claude 是另一回事**：g6/g7/g8/g9 四颗对 `claude.ai` 全部 403（Cloudflare 拦
机房 IP），换节点没用；浏览器带 TLS 指纹可能能过，但真被拦只能换住宅/商业出口。

## 09:00–09:05 第三轮：扫描后反而变慢 / DNS 自锁

用户重新扫描节点并重启代理后，反而比之前更差。两个原因都是上一轮改动带出来的：

1. **静态 IP 表会失配**。上一轮把分组写死成 4 个 IP（昨天 12:05 实测），
   用户一跑 `重新扫描节点`，`pinned.json` 的 tag/服务器全换，表对不上，
   分组退化成"全量节点、只按延迟选"，吞吐过滤失效。
   现在改成读 `node_deep.json` 的 `dl_kbps` 动态排序（rescan.py 每次都写），
   取前 4 颗（且不低于最快那颗 1/4），静态表只在没有深测数据时兜底。
2. **DoH 自锁**。上一轮把 DNS 的 `detour` 指到 `grp-any`，而 grp-any 的
   urltest 探针本身要解析域名 —— 探针等 DoH、DoH 等探针，结果 DNS 全超时、
   整机断网。现在 `detour` 固定走 `gai`(2098)，它有独立的解析与兜底路径。

另外两处：
- `google_bad.json` 是 11-21 手写的"Gemini 拒绝"名单，里面 `94.183.164.176`
  现在是深测第一名且 `chatgpt_ok`。Google 组已用 `gemini.google.com/robots.txt`
  做探针，运行时自己会踢人，静态黑名单只留作没深测数据时的兜底。
- 分组保留慢节点垫后：深测是快照，免费节点半小时能死一半（实测 08:08 第一名
  的 g0，08:59 已连不上）。只留 4 颗会直接断网，慢了至少还能用。

验证（09:02）：`nslookup gemini` 返回 142.251.15x.2；Gemini 3.9s、AI Studio
3.4s、ChatGPT 3.6s；10MB 上行 41s（244 KB/s）、1MB 下行 3.5s（287 KB/s）。

**09:06 收尾**：用户双击 `启动代理.bat` 重新接管隧道（pid 44292），AI 会话里的
保活任务已全部撤掉，隧道继续由用户窗口托管。此时 `grp-google` 落到 `gai`(2098)：
免费 vless 节点这一刻都没过 `gemini.google.com/robots.txt` 探针，兜底按设计生效——
Gemini 3.5s、AI Studio 2.1s、ChatGPT 3.5s，`nslookup gemini` 正常返回 142.251.155.2。

## 22:20–22:30 Amazon / AWS 下载慢

用户要下 Amazon Quick，页面 30s 打不开、点了半天才动。实测（同一 URL
aws.amazon.com/quick/download/）：

- 经 TUN（urltest 选的 g7）：30s 只下 12 KB/s
- 经 gai(2098)：99~129 KB/s
- 逐节点测：g6 67~118 KB/s 最好，g7 17、g3 15、g5 1.4、g0/g2 直接失败
- 直连（绕过隧道）：10 KB/s —— 所以直连也救不了，不是纯路由问题

结论：gstatic 探针选出的"最快"节点对 AWS 可能是最慢的（探针和目标站不同源）。
处理：新增 `grp-amazon` 组，探针用 `aws.amazon.com/robots.txt`（13KB），
成员是全部节点 + gai；`AMAZON_DL`（amazon.com / amazonaws.com / awsstatic.com
等）走这个组。改完首页从 30s/12 KB/s 变成 5.3s/79 KB/s，但池子本身对 AWS
只有 10~80 KB/s，大文件依旧慢 —— 这是免费节点的上限。
