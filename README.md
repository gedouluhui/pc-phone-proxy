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

**当前版本**：手机端 **v2.4**（2026-11-13）：新增**公开源一键导入**（七个公开聚合列表，运行时抓取、自动测速，
APK 内不含任何节点凭据）；另含 v2.3 的安全加固（`https://` 节点不再降级成明文、关闭应用备份、
订阅响应限 10 MB、显式放行 `http://` 订阅）。电脑端脚本随仓库 `main` 更新。

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

### 手机端（Android 7.0+，v2.4）

- **一键启动**：对节点池全部节点并发测速自动选最快；运行中由 Xray observatory 每 30 秒巡检，掉线自动切换
- **自动分流**：`geosite:cn` / `geoip:cn` / 私有地址直连，其余走代理
- **公开源一键导入**：内置 7 个公开聚合列表（GitHub raw + jsDelivr 镜像各一份），点一下就抓取、去重、测速；
  APK 里只有 URL，不含任何节点凭据，所以公开版也能直接用
- **导入灵活**：支持 `vless://` `vmess://` `trojan://` `ss://` 分享链接（每行一条）与 `http(s)` 订阅地址
- **TUN 模式**，无需 root；内置 arm64-v8a / armeabi-v7a / x86 / x86_64 四个 ABI
- 手动指定节点 / 自动模式；实时上下行速率；节点池为空时给出明确引导
- 不读短信、不读通讯录、无账号、无遥测

### 电脑端（Windows 10/11 x64）

- **一条命令建池**：抓取公开节点源 → TCP 初筛 → 下载/上传/ChatGPT 地区闸门深测 → 选出当前最快出口
- **三通道**：`general 2101`（ChatGPT/Claude）、`fast 2103`（Google/GitHub/HF/网页）、`cli 2090`（git/pip/curl/npm），另有 Reddit 2086、Steam 2096 可选出口
- **浏览器走 PAC 自动分流**，国内站点直连；命令行代理变量自动配置
- **看门狗自愈**：端口掉线、站点打不开、PAC 被改都会自动修复；检测失败时降级而不是拆掉唯一存活的栈
- **定期重扫**：默认每 6 小时自动重抓公开源 → 深测速度/ChatGPT → 重建出口，把更快的节点换上来（`PROXY_REFRESH_HOURS` 可调）
- 所有监听端口只绑定 `127.0.0.1`；`stop_proxy.py` 一键撤掉 PAC 与环境变量

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
PROXY_DIR=/path/to/代理便携版/_proxy python gen_pool.py   # 生成 24 个实测节点
PROXY_APK_OUT=/path/to/手机代理/手机代理.apk python build_apk.py
```

构建前确认 `assets/nodes.json` **不是 `[]`**；这个文件含凭据，只留本地，不要提交、不要上传 Release。两个 APK 同签名，可直接覆盖安装，无需卸载。

### 电脑端

目录布局（`pc/` 即 Windows 便携包里的 `_proxy`）：

```
pc/
├─ _proxy/
│  ├─ bin/sing-box.exe      ← 自行下载官方 release 放这里
│  ├─ harvest.py            ← 抓公开节点源
│  ├─ deep_test.py          ← 深测下载/上传/ChatGPT 闸门
│  ├─ bestroute.py          ← 选出出口，写 pinned.json + PAC
│  ├─ start_proxy.py        ← 启动出口组、装 PAC、复验
│  ├─ stop_proxy.py         ← 撤掉代理，恢复直连
│  ├─ watchdog.py           ← 后台自愈
│  ├─ pacroute.py           ← 本地 PAC 服务 + 分流名单
│  ├─ privacy_check.py      ← 隐私自检（只读）
│  └─ proxy_diag.py         ← 分流诊断（某域名该直连还是代理、哪条路可达）
├─ start-proxy.bat
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

日常使用：双击 `pc/start-proxy.bat` 启动，`pc/stop-proxy.bat` 关闭。

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
  cli 2090 / reddit 2086                     │
        │                                    ▼
  浏览器 / 命令行自动分流             Android TUN + Xray
```

手机端不自己实现协议栈：使用开源 **Xray-core**（经 AndroidLibXrayLite），导入链接与内置节点走同一个解析器，避免两套实现漂移。

---

## 构建

- **手机 APK**：见 [`phone/README.md`](phone/README.md)。不需要 Gradle，`phone/build_apk.py` 走 `javac → d8 → aapt2 → zip → zipalign → apksigner`；需要 JDK 17、Android SDK build-tools 与 [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite/releases) 的 `libv2ray.aar`。
- **电脑端**：纯 Python 脚本，无需构建；按上面的“准备”放好 `sing-box.exe` 即可。

---

## 已知限制

- 免费公开节点不稳定，速度与存活率随时间变化；本项目做的是“自动挑选 + 自动切换”，不能保证任何时候都有高速节点
- ChatGPT 有地区封锁，深测会淘汰部分节点；被淘汰不代表节点本身不可用
- 手机端仅 Android 7.0+，iOS 与 HarmonyOS NEXT 不支持
- 电脑端只在 Windows 10/11 x64 实测过

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
