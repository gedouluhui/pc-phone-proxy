# 手机 + 电脑 双端自动选线代理

**Windows 便携版 + Android APP**：自动抓取并实测公开免费节点，挑出当前最快、能过地区封锁的出口；节点掉线自动切换，国内外流量自动分流（国内直连）。两端共用一套节点池，**免费、开源、无账号、无遥测**。

> **本仓库不附带任何可用节点。** 节点是第三方免费资源，分享凭据等于分享密码。公共版 APK 不内置节点，安装后导入你自己的分享链接或订阅；电脑端脚本用于从公开源抓取、实测并建立你自己的节点池。

![手机端](docs/phone-connected.png)

<p>
<img alt="release" src="https://img.shields.io/github/v/release/gedouluhui/pc-phone-proxy?label=release">
<img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
<img alt="platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Android-lightgrey">
</p>

**当前版本**：手机端 **v2.1**（2026-11-11）· 电脑端脚本随仓库 `main` 更新

---

## 特性

### 手机端（Android 7.0+，v2.1）

- **一键启动**：对节点池全部节点并发测速自动选最快；运行中由 Xray observatory 每 30 秒巡检，掉线自动切换
- **自动分流**：`geosite:cn` / `geoip:cn` / 私有地址直连，其余走代理
- **导入灵活**：支持 `vless://` `vmess://` `trojan://` `ss://` 分享链接（每行一条）与 `http(s)` 订阅地址
- **TUN 模式**，无需 root；内置 arm64-v8a / armeabi-v7a / x86 / x86_64 四个 ABI
- 手动指定节点 / 自动模式；实时上下行速率；节点池为空时给出明确引导
- 不读短信、不读通讯录、无账号、无遥测

### 电脑端（Windows 10/11 x64）

- **一条命令建池**：抓取公开节点源 → TCP 初筛 → 下载/上传/ChatGPT 地区闸门深测 → 选出当前最快出口
- **三通道**：`general 2101`（ChatGPT/Claude）、`fast 2103`（Google/GitHub/HF/网页）、`cli 2090`（git/pip/curl/npm），另有 Reddit 2086、Steam 2096 可选出口
- **浏览器走 PAC 自动分流**，国内站点直连；命令行代理变量自动配置
- **看门狗自愈**：端口掉线、站点打不开、PAC 被改都会自动修复；检测失败时降级而不是拆掉唯一存活的栈
- 所有监听端口只绑定 `127.0.0.1`；`stop_proxy.py` 一键撤掉 PAC 与环境变量

---

## 快速开始

### 手机端

1. 到 [Releases](../../releases) 下载 `PhoneProxy-public.apk`（本地构建产物名为 `手机代理-公版.apk`，也可按 [`phone/README.md`](phone/README.md) 自行构建）。
2. Android 7.0 及以上；首次安装需允许“安装未知来源应用”。iOS 与 HarmonyOS NEXT 无法安装 APK。
3. 打开 App → 允许通知 → 点 **导入节点 / 订阅**，粘贴分享链接（每行一条）或订阅 URL。
4. 点 **启动代理** → 允许建立 VPN 连接 → 等待自动测速。
5. 状态变成“已连接”，用浏览器打开 `google.com` 验证。

> 节点池为空时 App 不会启动 VPN，会直接提示去导入——公共版不内置任何节点，避免公开别人的凭据。

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
│  └─ privacy_check.py      ← 隐私自检（只读）
├─ start-proxy.bat
└─ stop-proxy.bat
```

准备：

1. 安装 Python 3.10+，`pip install requests websocket-client`。
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
