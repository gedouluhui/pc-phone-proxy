# 手机 + 电脑 双端自动选线代理

**中文** · [English](README.en.md)

**Windows 便携版 + Android APP**：自动抓取并实测公开免费节点，挑出当前最快、能过地区封锁的出口；节点掉线自动切换，国内外流量自动分流（国内直连）。两端共用一套节点池，**免费、开源、无账号、无遥测**。

*An auto-selecting proxy for Windows and Android: it harvests public nodes, benchmarks them itself, and keeps domestic traffic direct — no account, no telemetry.*

所有功能全部免费开放：没有付费墙、没有订阅、不卖节点、不接广告；代码你可以自己审、自己改、自己编译。

> **本仓库不附带任何可用节点。** 节点是第三方免费资源，分享凭据等于分享密码。公共版 APK 不内置节点，但内置了**公开源一键导入**（APK 里只有几个公开聚合列表的 URL，运行时现抓，不含任何凭据）；也可以导入你自己的分享链接或订阅。

> **两个 APK，别装错**：Releases 里的 `PhoneProxy-public.apk` 是**去凭据公版**，装完点「导入节点 / 订阅 → 从公开源导入」即可抓到一批节点并自动测速；想装完完全不用点，就按 [`phone/README.md`](phone/README.md) 用 `gen_pool.py` 生成自己的节点池后**本地构建私用版**（`assets/nodes.json` 被 `.gitignore` 忽略，绝不能提交）。两者同签名，可直接覆盖安装。

![手机端](docs/phone-connected.png)

<p>
<img alt="release" src="https://img.shields.io/github/v/release/gedouluhui/pc-phone-proxy?label=release">
<img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
<img alt="platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Android-lightgrey">
</p>

**当前版本**：手机端 **v2.6**（2026-11-23）：导入与启动前先用**真 Xray 内核做零网络预检**，
过不了内核的节点直接隔离，不再出现「解析成功但一启动就整栈失败」；解析器抽成纯 JVM
`NodeConfigCodec`，配 333 条投毒语料 + 每条被接受节点过 `xray run -test` 的 CI 闭环；
AI 闸门缓存缩到 1 天，observatory 探针改为 16KB / 10 分钟。另含 v2.5 的 AI 出口闸门、
v2.4 的公开源一键导入与 v2.3 的安全加固（`https://` 不再降级成明文、关闭应用备份、订阅限流）。
电脑端脚本随仓库 `main` 更新：TUN 的 AI/Amazon 出口已合并进主实例（不再依赖 `2098` 旁路进程），
看门狗新增长期低速「假死流」判定，不会再把重建锁死 10 分钟。

---

## 目录

- [特性](#特性) · [快速开始](#快速开始) · [隐私设计](#隐私设计)
- [工作原理](#工作原理) · [构建](#构建) · [已知限制](#已知限制) · [许可与免责](#许可与免责)

## 适合谁

- 想装完直接能用（公版点「从公开源导入」即可抓到一批节点）、也能接受免费节点质量波动的人；
- 手上已有自己的订阅或分享链接、想统一管起来的人；
- 想用**同一套分流规则**同时管电脑和手机的人（敏感域直连、国内直连）。
- 不适合：要开箱即用、要稳定高速、要商业客服的场景——本项目不卖节点、不提供任何节点。

## 特性

### 手机端（Android 7.0+，v2.6）

- **一键启动**：对节点池全部节点并发测速自动选最快；运行中由 Xray observatory 每 10 分钟做一次
  16KB 探针（只量握手 + 小样本吞吐，兼顾移动流量），掉线自动切换
- **自动分流**：`geosite:cn` / `geoip:cn` / 私有地址直连，其余走代理
- **AI 出口闸门（v2.5）**：点「AI 闸门」对本机节点实测 `chatgpt.com` / `claude.ai`，
  只有两个探针都返回 200/204 的节点才进 `cg-balancer`，ChatGPT/Claude 只走它们；
  结果按节点指纹存 1 天，节点池变了重测一次即可（列表里标 `AI✓`）。没有这一步，
  公开源导入的节点全部没有地区资格，AI 域名只能交给随机出口 → 现象就是「能上网但 ChatGPT 403」
- **内核预检 / 隔离（v2.6）**：导入订阅和每次启动前，用真 Xray 内核做一次**零网络**
  配置校验（`measureOutboundDelay` 走到配置加载为止，探测 URL 故意非法，不发任何流量）；
  内核拒绝的节点会被标记并跳过，不会拖垮整条隧道。启动时若整批配置仍被内核拒绝，
  后台会自动隔离坏节点，下次启动只加载可用节点
- **公开源一键导入**：内置 7 个公开聚合列表（GitHub raw + jsDelivr 镜像各一份），点一下就抓取、去重、测速；
  APK 里只有 URL，不含任何节点凭据，所以公开版也能直接用
- **导入灵活**：支持 `vless://` `vmess://` `trojan://` `ss://` 分享链接（每行一条）与 `http(s)` 订阅地址
- **TUN 模式**，无需 root；内置 arm64-v8a / armeabi-v7a / x86 / x86_64 四个 ABI
- 手动指定节点 / 自动模式；实时上下行速率；节点池为空时给出明确引导
- 不读短信、不读通讯录、无账号、无遥测

### 电脑端（Windows 10/11 x64）

- **一条命令建池**：抓取公开节点源 → TCP 初筛 → 下载/上传/ChatGPT 地区闸门深测 → 选出当前最快出口
- **三通道**：`general 2101`（ChatGPT/Claude）、`fast 2103`（Google/GitHub/HF/Reddit/Steam/网页）、`cli 2090`（git/pip/curl/npm）
- **浏览器走 PAC 自动分流**，国内站点直连；命令行代理变量自动配置
- **双模式**：默认免管理员的分流模式；可选 **TUN 全局模式**（UAC 一次），商店/UWP/启动器等不认系统代理的程序也能用
- **静态代理兜底**：除 PAC 外同时写 `ProxyEnable=1 / ProxyServer=127.0.0.1:2090`。NVIDIA、打印机等驱动下载器只读静态代理，不再「0 字节失败」；浏览器仍按 PAC 分流（WinINET 规定 PAC 优先）
- **看门狗自愈**：端口掉线、站点打不开、PAC/静态代理被改都会自动修复；检测失败时降级而不是拆掉唯一存活的栈
- **下载保护 + 假死流放行**：clash API 检测到 >20 MB 的活动下载时延后重建 10 分钟，不打断驱动安装包；
  若大流量已持续 ≥60 秒但速率跌到 30 KB/s 以下，且深测池里有 3 倍以上的备选节点，则判定为
  「低速假死流」并放行重建，不会为了保护一个卡死的下载把整条线路锁死
- **一键体检**：`check-proxy.bat` 按依赖顺序跑「TUN 模式 → 出口端口 → PAC 内容 → 静态代理 → 7 个站点实测 → 出口身份 → 看门狗」，第一个 FAIL 就是根因所在层
- **定期重扫**：默认每 12 小时自动重抓公开源 → 深测速度/ChatGPT → 重建出口，把更快的节点换上来（`PROXY_REFRESH_HOURS` 可调）
- **真关闭**：`stop_proxy.py` 撤 PAC、杀看门狗/TUN/全部自家 sing-box、还原注册表与用户环境变量，并逐项实测直连；`ENABLED` 标志保证关掉后没有任何进程把代理写回来
- 所有监听端口只绑定 `127.0.0.1`；TUN 模式的虚拟网卡随 sing-box 进程退出而释放

#### 电脑端端口一览

| 端口 | 用途 | 说明 |
|---|---|---|
| 2101 / 2100 | general HTTP / SOCKS | ChatGPT、Claude 等需要地区合格的站点 |
| 2103 / 2102 | fast HTTP / SOCKS | Google、GitHub、HF、Reddit、网页 |
| 2090 | cli（mixed） | git/pip/curl/npm 与静态代理兜底 |
| 2098 / 2099 | Google AI 专用 HTTP / SOCKS | **仅分流模式**；TUN 已把 AI 组内建进主实例 |
| 2096 / 2097 | Steam 美区 HTTP / SOCKS | 仅在找到可用美区出口时监听 |
| 2086 / 2085 | 香港节点 HTTP / SOCKS | 仅在深测池有 HK 候选时监听（Reddit） |
| 19090 | Clash API（分流） | 只给看门狗/诊断读状态 |
| 19091 | Clash API（TUN） | 与分流错开，避免抢 9090 默认端口 |
| 8891 | 本地 PAC 服务 | 被占用时自动换 8892–8900 |

---

## 快速开始

### 手机端

**A. 用 Releases 公版（装完点一下就有节点）**

1. 到 [Releases](../../releases) 下载 `PhoneProxy-public.apk`（本地构建产物名为 `手机代理-公版.apk`）。
2. Android 7.0 及以上；首次安装需允许“安装未知来源应用”。iOS 与 HarmonyOS NEXT 无法安装 APK。
3. 打开 App → 允许通知 → 点 **导入节点 / 订阅** → **从公开源导入**。
   它会依次抓 7 个公开聚合列表（单个源失败自动换 jsDelivr 镜像），去重后最多收 120 条，然后自动测速。
4. 点 **启动代理** → 允许建立 VPN 连接 → 默认「自动选线」会走当前最快且可用的节点。
   状态变成“已连接”后用浏览器打开 `google.com` 验证。
5. 抓不到或想用固定节点：同一入口选「粘贴分享链接 / 订阅地址」，填自己的订阅。

> **为什么不在 APK 里直接塞节点**：那等于把别人的节点凭据公开到仓库里，凭据会立刻被刷爆，
> 用的人越多死得越快。公开源的做法是"只带地址、用时现抓"，仓库干净，节点也随公开列表更新。
> 代价是公开列表质量参差：实测能用，但不保证长期稳定，重要账号请按下面的隐私说明走直连。

**B. 本地构建内置节点版（装完直接启动）**

```bash
cd phone
PROXY_DIR=/path/to/代理便携版/_proxy python gen_pool.py   # 目标 24 个，可用不足时自动收缩
PROXY_APK_OUT=/path/to/手机代理/手机代理.apk python build_apk.py
```

构建前确认 `assets/nodes.json` **不是 `[]`**；这个文件含凭据，只留本地，不要提交、不要上传 Release。两个 APK 同签名，可直接覆盖安装，无需卸载。

### 电脑端

目录布局（`pc/` 即 Windows 便携包里的 `_proxy`）：

```
pc/
├─ _proxy/
│  ├─ bin/sing-box.exe      ← 自行下载官方 release 放这里
│  ├─ bin/wintun.dll        ← 仅 TUN 模式需要（官方签名 0.14.1，可从 sing-box release 或 wintun.net 获取）
│  ├─ harvest.py            ← 抓公开节点源
│  ├─ deep_test.py          ← 深测下载/上传/ChatGPT 闸门
│  ├─ bestroute.py          ← 选出出口，写 pinned.json + PAC
│  ├─ start_proxy.py        ← 启动出口组、装 PAC + 静态代理、复验
│  ├─ stop_proxy.py         ← 完整停止：看门狗→TUN→PAC→进程→还原注册表/环境变量→实测
│  ├─ tun_mode.py           ← 可选 TUN 全局模式（自提权、生成 singbox_tun.json）
│  ├─ watchdog.py           ← 后台自愈（ENABLED 标志缺失即退出，绝不写回）
│  ├─ sysstate.py           ← 注册表/环境变量快照、静态代理、原样还原
│  ├─ pacroute.py           ← 本地 PAC 服务 + 分流名单
│  ├─ doctor.py             ← 一键体检（分流/TUN 双模式）
│  ├─ privacy_check.py      ← 隐私自检（只读）
│  └─ proxy_diag.py         ← 分流诊断（某域名该直连还是代理、哪条路可达）
├─ start-proxy.bat
├─ check-proxy.bat          ← 体检入口
└─ stop-proxy.bat
```

准备：

1. 安装 Python 3.10+，`pip install -r pc/_proxy/requirements.txt`（`requests` / `websocket-client` / `aiohttp`）。
2. 从 [SagerNet/sing-box releases](https://github.com/SagerNet/sing-box/releases) 下载 Windows amd64 的 `sing-box.exe`，放到 `pc/_proxy/bin/`。
3. 如果所在网络访问 GitHub raw 需要前置代理，设置 `BOOT_PROXY=http://127.0.0.1:端口`；能直连就不用设。

首次建立节点池并启动：

```bat
cd pc\_proxy
python harvest.py
python deep_test.py
python bestroute.py --apply
python start_proxy.py
```

日常使用：双击 `pc/start-proxy.bat` 启动分流模式；需要 TUN 全局模式时双击
`pc/tun-mode.bat`（需 UAC，并把官方签名的 `wintun.dll` 放进 `pc/_proxy/bin/`）；
`pc/stop-proxy.bat` 完整关闭（含 TUN）并实测直连。

> 免费节点寿命有限。看门狗会在整池失效时自动重扫（12 小时最多一次），也可手动重跑 `harvest.py` → `deep_test.py` → `bestroute.py --apply`。

---

## 隐私设计

### 默认开启的保护

| 保护 | 做法 | 效果 |
|---|---|---|
| **敏感域不进隧道** | 银行/支付/政务/社保/税务/教育 29 条域名强制直连（`pacroute.SENSITIVE`，手机端与 PC 端同一份名单） | 账号类站点不会出现在免费节点上 |
| **明文 HTTP(80) 直连** | PAC + sing-box 双规则 | 节点看不到明文 URL 与内容 |
| **DNS(53) 直连** | sing-box 路由规则 | 解析不被节点篡改 |
| **UDP/QUIC 拒绝** | 经代理的 UDP 一律 reject，浏览器自动回落 TCP | 减少绕过 TLS 的暴露面 |
| **内网段直连** | `127.*` / `10.*` / `172.16-31.*` / `192.168.*` | 内网地址不会误进隧道 |
| **一键自检** | `python pc/_proxy/privacy_check.py` | 检查出口 IP、明文泄露、敏感域覆盖、系统根证书（MITM） |
| **分流诊断** | `python pc/_proxy/proxy_diag.py modelscope.cn` | 看某域名被判直连还是代理，以及直连/2103/2101/2090 哪条路真的通 |

### 防不住的部分（任何代理客户端都做不到）

- 免费节点运营者必然能看到：你的真实 IP、访问的**域名**（TLS SNI / CONNECT 主机名）、访问时间与流量大小
- 节点可以记录这些元数据，也可以对**未加密**流量做替换；HTTPS 正文有 TLS 保护，除非你手动装过对方的根证书
- 浏览器 WebRTC 可以绕过代理暴露本机地址，隐私要求高时请关闭 WebRTC

> 结论：**不要用免费节点登录网银、支付、公司系统等敏感账户**（本项目已把这类域名强制直连）；更换节点后建议跑一次 `privacy_check.py`。

---

## 工作原理

```
公开节点源 ──harvest──> candidates.jsonl
                          │
                    deep_test（TCP / 下载 / 上传 / ChatGPT 地区闸门）
                          │
                     node_deep.json
                          │
        ┌─────────────────┴──────────────────┐
        │ bestroute.py --apply               │ gen_pool.py
        ▼                                    ▼
  sing-box 出口组 + PAC              assets/nodes.json
  general 2101 / fast 2103           （手机端内置池）
  cli 2090                          │
        │                                    ▼
  浏览器 / 命令行自动分流             Android TUN + Xray
```

手机端不自己实现协议栈：使用开源 **Xray-core**（经 AndroidLibXrayLite），导入链接与内置节点走同一个解析器，避免两套实现漂移。

---

## 构建

- **手机 APK**：见 [`phone/README.md`](phone/README.md)。不需要 Gradle，`phone/build_apk.py` 走 `javac → d8 → aapt2 → zip → zipalign → apksigner`；需要 JDK 17、Android SDK build-tools 与 [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite/releases) 的 `libv2ray.aar`。
  解析器回归：`python phone/tools/check_poison.py` 会编译纯 JVM 解析器，喂 333 条投毒样本，
  并把每条被接受的节点和完整配置交给真 Xray `run -test`；CI 的 `android` job 已接入，规则漂移会直接红灯。
- **电脑端**：纯 Python 脚本，无需构建；按上面的“准备”放好 `sing-box.exe` 即可。

---

## 已知限制

- 免费公开节点不稳定，速度与存活率随时间变化；本项目做的是“自动挑选 + 自动切换”，不能保证任何时候都有高速节点
- ChatGPT 有地区封锁，深测会淘汰部分节点；被淘汰不代表节点本身不可用
- 手机端仅 Android 7.0+，iOS 与 HarmonyOS NEXT 不支持
- 电脑端只在 Windows 10/11 x64 实测过

---

## V3 变更（2026-11-19）

针对「关不掉、下载器失败、用着用着断网」这一轮问题：

1. **关闭是真的关闭**。旧实现只撤 PAC，看门狗 120 秒后把 PAC 写回；现在
   关闭先删 `ENABLED` 权限标志（看门狗与 PAC 守夜人看到即收手），再按
   「TUN → 看门狗 → PAC/守卫 → 全部自家 sing-box/辅助进程 → 还原注册表与
   用户环境变量」顺序停止，最后逐项验证端口、进程、注册表、环境变量并实测直连。
2. **不认 PAC 的程序也能走代理**。启动时同时写 `ProxyEnable=1` 和
   `ProxyServer=http(s)=127.0.0.1:2090`；WinINET 规定 PAC 优先，所以浏览器
   分流不变，NVIDIA/打印机安装器、部分 Qt/UWP 程序拿到静态值后由 2090 再分流。
   关闭时按启动前快照原样还原；无快照时只清「指向死环回端口」的旧值。
3. **下载域名进 PAC**：NVIDIA/GeForce、AMD、Intel、HP、Canon、Epson、Brother、
   Dell、微软下载/更新 CDN。
4. **少折腾**：urltest 容差 150→400ms（防抖动来回换节点）；站点闸门 2→3 次
   才重建；重建冷却 600→900s；clash API 检测到 >20 MB 活动下载时延后 10 分钟；
   深测池不足时复用 `pinned.json` 里上一批节点作为候选，不再「没候选就断网」。
5. **TUN 全局模式**（可选）：`tun_mode.py` 用 wintun 创建 `pcproxy` 虚拟网卡，
   自请求 UAC；与分流模式互斥（先停分流栈）；关闭时杀验证过镜像名/命令行的
   sing-box 并删除标记。TUN 配置同样先过 `sing-box check`。
6. **体检适配 TUN**：TUN 运行时不再误报端口/PAC/环境变量全红，逐站测试改为
   直连探测；新增「TUN 模式」检查项。
7. 修复 GBK 控制台遇到 emoji 触发 `UnicodeEncodeError` 导致兜底路径中断的问题。

## V3.1 变更（2026-11-20）

这一轮修的是「开不起来、开起来也不稳、关了还有幽灵」——全部来自实机日志：

1. **幽灵 TUN**。上一版从 A 目录启动过 TUN，之后换到 B 目录，`TUN_ACTIVE`
   标记留在 A 里，B 的关闭流程看不到它；那个**提权**的 sing-box 一直活着，
   占着 `pcproxy` 网卡劫持全部流量、占着 clash 控制端口。表现是「所有节点
   都像死了」。现在按 `pcproxy` 网卡 + 控制端口 + 空命令行（提权进程读不到
   命令行）三重特征识别，必要时请求一次 UAC 清掉。
2. **控制端口不再用 9090**。9090 是 Clash 系默认端口，Clash Verge / mihomo /
   旧副本都可能占着它，我们的出口会 `bind: Only one usage of each socket
   address` 直接 FATAL 退出，日志看起来却像「节点全挂」。分流用 19090，
   TUN 用 19091，互不抢。
3. **多副本互斥**。关闭时按项目签名（`_proxy\watchdog.py` 等）清理**所有**
   副本，不再只清当前目录；启动时若发现别的副本在跑，先关掉再继续，避免
   两套栈抢同一批端口。
4. **fast 组至少 3 个成员**。之前 2103 常常只有 1 个成员，那颗节点一抖，
   浏览器和 CLI 立刻「没网」。urltest 会跳过死成员，加宽列表没有代价。
5. **兜底不再接公网代理**。深测组起不来时，旧逻辑会从候选里挑一个公网
   HTTP 代理写进系统代理（实测写成了 `4.144.146.21:80`，闸门全红），既慢
   又不可信。现在只接受 `127.0.0.1`，否则撤销并保持直连，提示重扫。

## V3.2 变更（2026-11-23）

1. **TUN 不再外挂 `2098`**。原先 TUN 为了避开 DoH 与 `urltest` 的解析死锁，
   另起一个 sing-box 监听 `2098`，TUN 再用本地 HTTP outbound 串过去：多一跳、
   多一个进程、还是一个没有看门狗的单点。现在 `grp-google` / `grp-amazon`
   直接由主实例内的 pinned 节点组成，DoH 走 IP 字面量探针的 `grp-dns`，
   AI 出口仍按 Google 拒绝名单筛选并保留 urltest 故障转移。`2098/2099`
   只保留给分流模式。
2. **低速假死流放行**。看门狗不再只看「累计 >20MB」：取两次 Clash API 快照算
   实时速率，只有所有大流量都年满 60 秒且低于 30KB/s、并且深测池里存在
   3 倍以上备选节点时，才放行重建并记录「低速假死流放行」。真正在下载的
   大流量仍然受保护。
3. **PC 解析器投毒加固**。`nodes.py` 拒绝空主机/空端口/端口越界/空 UUID
   与空 SS 加密方式；`tests_ci/test_poison_parse.py` 用 240+ 变异链接保证
   解析器不抛异常、被接受的出口结构可信，危险主机仍由 `load_nodes` 过滤。
4. **可移植性**：`pacroute.py` 的 `winreg` 改为非 Windows 下可导入，
   `tests_ci` 可在 Linux 运行。

## 分流自愈（2026-11-18）

这一轮修的是「明明出口都活着，浏览器里 Claude 打不开」——由四个各自都不报错的
缺陷接力造成，任何一个单独修都看不出效果：

1. `autoroute.py --apply` 无参调用 `apply_pac()`，落到静态默认端口（`9910` 迷雾通
   未运行 / `2086` 在 pinned 配置里根本没有 inbound），把看门狗写对的 PAC 覆盖掉；
2. `apply_pac()` 不校验端口存活，照样写出 **fail-closed**（故意不带 `; DIRECT`）的
   `GENERAL` 规则 → 浏览器硬断；
3. 看门狗的 PAC 自愈只比对 URL 和「PAC 服务器活着」，不比对内容 → URL 没变，
   永不修复；
4. `autoroute` 的探针只发 UA。`claude.ai` 对「只有 UA 的 curl」返 403 Cloudflare
   挑战，而补齐 `Accept / Accept-Language / sec-ch-ua` 的同一个出口是 302 →
   anthropic 组每轮都被判「全灭」，从 `route_map.json` 里消失。

现在的行为：

- `apply_pac()` 先把 `general/fast` 换成**真的在监听**的端口；一个活出口都没有时
  **拒绝写 PAC**（`ok=False`），不再把 fail-closed 规则指向空端口。
- 看门狗从 PAC 服务取回正文，解出 `GENERAL` 实际指向的端口，任一不监听就重建。
- `autoroute` 先对每个出口实打一次 HTTPS，上游已死的出口（端口在、上游 reset）
  不参与测速；整组不可用时**沿用旧路由**，不再把这组删掉。
- 两个探针都发浏览器请求头。
- `autoroute` 加单实例锁：看门狗的定时任务和手动执行不会同时打同一批出口。
- PAC 的回落链去重（`PROXY 2103; PROXY 2103; ...` 会让浏览器对死端口多等一轮）。

还有一条：看门狗会无声消失。`finally` 不跑、日志一行不写、状态文件停在最后一刻 ——
是被 TerminateProcess。查下来的结论是**外部 job 对象回收**（`CREATE_BREAKAWAY_FROM_JOB`
返回「拒绝访问」），不是这几行代码自己退出的。因此不再赌「谁把它拉起来」，改成互相保活：

- `pacroute.py serve` 里起一个 60 秒的守护线程：`watchdog.pid` 不是活的 python 就重拉看门狗，
  连续秒退退避 15 分钟，见到 `STOP_WATCHDOG` 就闭嘴；
- 看门狗本来就会在 PAC 服务挂掉时 `pac_apply`，两者互为守夜人；
- `watchdog.py` 加 `faulthandler` → `logs/watchdog_crash.log`：硬崩溃留栈、被杀留空文件；
- 两处 spawn 的 `DETACHED_PROCESS | CREATE_NO_WINDOW` 改成
  `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`（和 PAC 服务一致，前者那个组合本身是矛盾的）。

配套加了 `doctor.py` / `check-proxy.bat` 体检，和 `tests_ci/test_route_selfheal.py`
（把上面四条不变量钉进 CI，含「无活出口时必须拒绝写 PAC」「探针必须带浏览器头」
「无香港候选时不得反复重启」）。

---

## 安全加固（2026-11-14）

这一轮按安全审计把 P0 问题清掉了，**其中两项会改变默认行为**：

**会感知到的变化**

1. **PAC 的默认兜底走「快出口 → 通用出口 → 直连」**：未收录的国外站会先试节点，只有国内/内网/银行政务域名直连（`DOMESTIC` / `SENSITIVE` / `DIRECT` 三张表）。打不开某站就先跑 `check-proxy.bat` 看是哪个出口断了，别急着改名单。
2. **`GENERAL`（ChatGPT / Claude 等）改成 fail-closed**：不再带 `; DIRECT` 回落。节点重建的那几秒里宁可报错，也不把真实 IP 裸发给运营商。

**修掉的问题**

- 看门狗 `fast` / `cli` 探针原来用 `http://…generate_204`，而路由表把 80 端口强制直连——探针根本没经过节点，节点全死也报绿灯；已改 HTTPS，并给 ChatGPT 门加了 Cloudflare 挑战页识别（`Just a moment` / `challenge-platform` / `unsupported_country`）。
- `deep_test.py` 上传测速的计时点写在了 `drain()` 之前，只量到写内存缓冲，上传带宽虚高几十倍，污染选线排序；已把计时移到「真正写出 + 收到响应头」之后。
- 订阅 URI 不再进日志和报告：`ACTIVE.json`、`nodes_alive.json`、`pinned_health` 全部走 `redact_uri()`，只剩 `scheme://***@host:port`。
- 订阅里的节点如果指向 `127.0.0.1` / `10.*` / `169.254.*` / `100.64.*` / IPv6 私网 / `*.local`，直接丢弃（防止把本机代理当内网扫描跳板）；HTTP 节点的 TLS 默认校验证书，只有订阅显式写 `allowInsecure=1` 才跳过。
- PAC 补上 `169.254.*`、`100.64/10`、IPv6 私网与 `.local/.lan/.internal/.corp` 直连；`NO_PROXY` 补 RFC1918。
- 杀进程前先做三元组核验（镜像名 + 命令行含本目录），避免 PID 被内核复用后误杀别人的进程。
- Android：VPN 接管 IPv6（原来只加 `0.0.0.0/0`，双栈网络下 v6 全量泄漏）；嗅探补 `quic`；阻断 `UDP/443` 与 `853`（Private DNS）。
- `build_apk.py` 解压 `libv2ray.aar` 防 ZipSlip；发布构建不允许沿用演示口令 `android`（设 `PROXY_KS_PASS`）。

**新增门禁**：`.github/workflows/ci.yml` 每次 push 跑 `compileall` + `tests_ci/test_pacroute.py`（PAC 分流 / SSRF / 脱敏断言）+ `tests_ci/test_route_selfheal.py`（出口存活自愈 / 探针身份 / 无候选不重启）+ `phone/check_release.py`。

---

## 许可与免责

本项目代码使用 MIT 许可证，见 [`LICENSE`](LICENSE)。第三方组件（Xray-core、AndroidLibXrayLite、sing-box、geoip/geosite 数据）遵循各自许可证，见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

本工具用于个人学习与访问公开的互联网资源；请遵守你所在地区的法律法规，不要用于任何违法用途。

---

## 反馈

提 [Issue](../../issues) 时请附：系统与版本（Windows 版本 / Android 版本 / APK 或脚本版本）、
哪一步出的问题、`proxy_diag.py` 或 `privacy_check.py` 的输出。**不要贴节点分享链接、订阅地址或截图里的凭据**。

---

## 同作者的其他项目

- [LuHui播放器](https://github.com/gedouluhui/luhui-player) —— mpv 内核 + 手绘 Fluent 外壳的 Windows 本地视频播放器
- [LuHui音乐播放器](https://github.com/gedouluhui/luhui-music-player) —— WinUI 3 + WASAPI 独占的本地音乐播放器
- [番茄闹钟](https://github.com/gedouluhui/fanqie-alarm) —— 整个应用就是一个 HTML 的番茄钟
