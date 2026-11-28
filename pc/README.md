# 电脑端

## 安装版与便携版

- 便携版保持免安装，状态默认写在 `_proxy` 内，**不会注册提权计划任务**。
- 安装版把 broker、sing-box、wintun 和 Python 放在 `Program Files\PhoneProxy`，可变状态放在 `%LOCALAPPDATA%\PhoneProxy\data`；broker 每次启动 TUN 前核验安装清单哈希、ACL 和数据目录。
- 托盘提供连接、断开、TUN/分流切换、体检和更新入口；更新只暂存已验签且 SHA-256 匹配的安装包，不覆盖当前安装。
- 安装脚本是 `installer/PhoneProxy.iss`；发布前准备 `runtime/python` 与 `runtime/tray.exe`，并用 Inno Setup 7.1.1 编译。2026-11-28 已实际生成 `dist/PhoneProxy-Setup-4.0.0.exe` 并通过 `python check_release.py` 的 PE/防泄漏检查；本机包未代码签名，正式发布前必须签名。
- 更新器从 `app/release_tools` 加载验签模块；安装清单把这些模块纳入哈希与必需文件，缺失即拒绝启动 broker/更新。

一套运行在 Windows 10/11 x64 上的本地代理栈：

一套运行在 Windows 10/11 x64 上的本地代理栈：

- 从公开节点源抓取候选，自动做 TCP 初筛、延迟、下载、上传、ChatGPT 地区闸门深测；
- 选出 `general`（ChatGPT/Claude）与 `fast`（Google/GitHub/HF/网页）两组出口；
- 用 sing-box 在 `127.0.0.1` 上开端口，浏览器通过本地 PAC 自动分流，命令行通过环境变量分流；
- 看门狗在后台自愈：端口掉线、站点打不开、PAC 被别的软件改掉，都会自动修复；
- 默认免管理员分流；可选 TUN 全局模式（wintun 虚拟网卡，UAC 一次），覆盖不认系统代理的程序；
- 除 PAC 外同时写静态代理 `127.0.0.1:2090`，NVIDIA/打印机等只读 ProxyServer 的下载器也能走代理；
- 一键关闭：撤 PAC/静态代理、杀全部自家进程、还原环境变量，并逐项验证直连。

## 目录与依赖

```
pc/
├─ _proxy/
│  ├─ bin/sing-box.exe     ← 自行下载（SagerNet/sing-box，Windows amd64）
│  ├─ harvest.py           抓公开源
│  ├─ deep_test.py         初筛 + 延迟 + 下载/上传/ChatGPT 深测
│  ├─ bestroute.py         打分选出口，--apply 写 pinned.json + PAC + 启进程
│  ├─ start_proxy.py       日常启动：复用/重建 -> 装 PAC -> 复验 -> 看门狗
│  ├─ stop_proxy.py        完整关闭并逐项验证（TUN/看门狗/进程/注册表/环境变量）
│  ├─ tun_mode.py          可选 TUN 全局模式（自提权，wintun 虚拟网卡）
│  ├─ watchdog.py          后台自愈
│  ├─ pacroute.py          本地 PAC HTTP 服务（默认 8891，被占用自动换 8892-8900）
│  ├─ sysstate.py          备份/恢复 WinINET、静态代理与环境变量
│  ├─ proxyctl.py          进程/PID/端口小工具
│  └─ ...                  站点探针、报告等
├─ start-proxy.bat
├─ tun-mode.bat
└─ stop-proxy.bat
```

Python 3.10+，依赖：

```bat
pip install -r _proxy\requirements.txt
```

（`requests`、`websocket-client`、`aiohttp`；`deep_test.py` 在函数内 import aiohttp，
旧文档漏写会导致 `ModuleNotFoundError`。）

`sing-box.exe`：<https://github.com/SagerNet/sing-box/releases> 下载 `sing-box-*-windows-amd64.zip`，把 `sing-box.exe` 放到 `pc/_proxy/bin/`。

TUN 模式还需要 `<https://www.wintun.net/>` 的 `wintun.dll`（0.14.1，WireGuard LLC 签名），同样放进 `pc/_proxy/bin/`；只做分流可以不装。

## 首次建立节点池

在 `pc/_proxy` 目录下：

```bat
python harvest.py
python deep_test.py
python bestroute.py --apply
```

- `harvest.py`：并行抓取内置的公开 HTTP/SOCKS/V2Ray 订阅源，写入 `candidates.jsonl`。默认直连；如果 GitHub raw 需要前置代理，先设置
  `set BOOT_PROXY=http://127.0.0.1:端口`。
- `deep_test.py`：TCP 初筛 → 延迟 → 下载/上传 → ChatGPT 地区闸门；结果写入 `node_deep.json`。默认 `--deep-k 96 --workers 4`，机器越好可以适当加大。
- `bestroute.py --apply`：按分数选出两组节点，生成 `pinned.json`、`proxy.pac`，启动 sing-box 出口组并复验。阈值可用 `--min-dl/--min-ul/--top` 调整。

> 深测和选路都会打印节点地区、协议、速度，不会打印 UUID/密码。

## 日常使用

```bat
start-proxy.bat
```

做四件事：

1. 如果出口已经在跑，直接复用；否则按 `pinned.json` 重建；
2. 启动本地 PAC 服务并把当前用户的 WinINET `AutoConfigURL` 指向它；
3. 逐个站点复验（ChatGPT / Google / GitHub / Kaggle / HuggingFace 等），失败时先原地重试，再按深测库重建；
4. 拉起 `watchdog.py`（单实例守护），后台每 60 秒检查端口、每 5 分钟检查关键站点。

TUN 全局模式（可选，需管理员）：

```bat
tun-mode.bat
```

TUN 只启动一个 sing-box 实例：`grp-google`（Gemini 探针）、`grp-amazon`
（AWS 探针）和 `grp-dns`（IP 字面量探针）都由主配置内的节点组成，DoH 的
detour 指向 `grp-dns`。它不会再拉起分流模式的 `2098`；启动 TUN 时那个端口
会被一并收掉，停止 TUN 后由下次分流启动重新创建。

关闭：

```bat
stop-proxy.bat
```

先删 `ENABLED` 权限标志，再按「TUN → 看门狗 → PAC/守卫 → 全部自家 sing-box → 还原注册表与环境变量」停止，最后逐项验证端口、进程、注册表和直连。TUN 运行时会再请求一次 UAC。

## 端口与分流

| 端口 | 用途 |
|---|---|
| 2101 http / 2100 socks | `general`：ChatGPT / Claude / OpenAI，只放能过地区闸门的节点 |
| 2103 http / 2102 socks | `fast`：Google / GitHub / HuggingFace / 普通网页 |
| 2090 mixed | 命令行（git/pip/curl/npm）与静态代理兜底：按域名再分流到上面两组 |
| 2086 http / 2085 socks | 香港单节点（Reddit；深测池没有 HK 时不存在） |
| 2096 http / 2097 socks | Steam 专用（可选；拿不到可用美国出口时回落到 2103） |
| 2098 http / 2099 socks | Google AI 专用出口：**仅分流模式**。TUN 已把 AI 组内建进主实例，不再启动这两个端口 |
| 8891（或 8892-8900） | 本地 PAC 服务，地址带内容哈希 `?v=<sha1前8位>` |
| 19090 / 19091 | sing-box Clash API（分流 / TUN，仅本机，供看门狗切换/观测） |

**直连优先**（2026-11-20 起）：内置 `rulesets/geoip-cn.srs`，目标 IP 在中国境内
一律直连，域名列表只负责需要提前分流的站点。`DRIVER_DIRECT`（NVIDIA/AMD/Intel/
HP/Canon/Epson/Brother/Dell、Windows Update、微软下载 CDN）强制直连——厂商按出口
IP 分配 CDN，走节点会拿到境外源，大文件必断。Steam 商店与壁纸引擎创意工坊在直连
判定之前显式走代理，`steamcontent` 等下载 CDN 仍直连。

分流规则在 `pacroute.py` 里维护：Google AI 域名优先走 2098，`general` 域名走
2101，`fast` 域名走 2103，其余按 `geoip-cn` 判定后决定直连或走 2103。

## 看门狗与自愈

- **单实例**：启动时读 `watchdog.pid`，若同 PID 文件指向另一个存活的 Python 进程，直接退出，避免双看门狗互相覆盖。
- **端口检查**：60 秒一次；连续失败才触发重建（有 900 秒冷却）。
- **站点闸门**：300 秒一次 ChatGPT / gstatic；连续 3 次失败才重建；检测到 Clash API 上有 >20 MB 活动下载时延后 10 分钟，不打断驱动安装包。
- **假死流放行**：延后前会取两次 Clash API 快照（间隔 4 秒）算实时速率。只有全部大流量都持续 ≥60 秒且低于 30 KB/s，并且 `node_deep.json` 里存在 3 倍以上速度的备选节点时，才放行重建，日志写「低速假死流放行」；正常下载仍然受保护。
- **PAC 检查**：120 秒一次，对比 `pac_url.txt` 里记录的实际地址，并确认本地 PAC 服务返回的内容与磁盘 `proxy.pac` **逐字节一致**；不一致会重装。静态代理被改掉也会写回。
- **整池失效**：最多 12 小时重扫一次公开源（`harvest.py` + `deep_test.py`）。
- **降级优先**：任何“检测失败就重建”的路径都不会先拆掉唯一存活的栈；`bestroute.py --apply` 在 fast 组检测不过时会把 fast 角色降级到 general 门，而不是拒绝应用导致全断。

## 常见问题

**浏览器打不开网页，但 `curl` 正常**
浏览器只在启动时读取 PAC。完全退出浏览器再打开；或在 `设置 → 网络 → 代理` 里确认“使用自动配置脚本”指向 `pac_url.txt` 里的地址。

**PAC 端口被别的程序占了**
`pacroute.py` 会从 8891 起向后找空端口（8892-8900），实际地址写在 `_proxy/pac_url.txt`。系统设置与看门狗都读这个文件，不要手工改回 8891。

**命令行不走代理**
已经打开的终端不会自动更新环境变量；关掉重开。新终端里 `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY` 应指向 `127.0.0.1:2090`。

**节点全挂了**
重跑 `harvest.py` → `deep_test.py` → `bestroute.py --apply`。免费节点寿命有限，这是正常维护动作。

**想确认当前出口 IP**
在命令行代理窗口执行：

```bat
curl -s https://www.cloudflare.com/cdn-cgi/trace
```

看 `ip=` 与 `loc=`。

## 许可

脚本使用 MIT。sing-box 为 GPL-3.0-or-later，需自行下载；公开节点属于第三方。详见仓库根目录 `THIRD_PARTY_NOTICES.md`。
