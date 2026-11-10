# 电脑端：Windows 自动选线代理

一套运行在 Windows 10/11 x64 上的本地代理栈：

- 从公开节点源抓取候选，自动做 TCP 初筛、延迟、下载、上传、ChatGPT 地区闸门深测；
- 选出 `general`（ChatGPT/Claude）与 `fast`（Google/GitHub/HF/网页）两组出口；
- 用 sing-box 在 `127.0.0.1` 上开端口，浏览器通过本地 PAC 自动分流，命令行通过环境变量分流；
- 看门狗在后台自愈：端口掉线、站点打不开、PAC 被别的软件改掉，都会自动修复；
- 提供一键关闭，撤掉 PAC/环境变量，恢复直连。

## 目录与依赖

```
pc/
├─ _proxy/
│  ├─ bin/sing-box.exe     ← 自行下载（SagerNet/sing-box，Windows amd64）
│  ├─ harvest.py           抓公开源
│  ├─ deep_test.py         初筛 + 延迟 + 下载/上传/ChatGPT 深测
│  ├─ bestroute.py         打分选出口，--apply 写 pinned.json + PAC + 启进程
│  ├─ start_proxy.py       日常启动：复用/重建 -> 装 PAC -> 复验 -> 看门狗
│  ├─ stop_proxy.py        一键关闭并逐项验证
│  ├─ watchdog.py          后台自愈
│  ├─ pacroute.py          本地 PAC HTTP 服务（默认 8891，被占用自动换 8892-8900）
│  ├─ sysstate.py          备份/恢复 WinINET 与环境变量
│  ├─ proxyctl.py          进程/PID/端口小工具
│  └─ ...                  站点探针、报告、便携包构建等
├─ start-proxy.bat
└─ stop-proxy.bat
```

Python 3.10+，依赖：

```bat
pip install requests websocket-client
```

`sing-box.exe`：<https://github.com/SagerNet/sing-box/releases> 下载 `sing-box-*-windows-amd64.zip`，把 `sing-box.exe` 放到 `pc/_proxy/bin/`。

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

关闭：

```bat
stop-proxy.bat
```

停止看门狗、sing-box、PAC 服务，恢复系统代理设置与命令行环境变量，并逐项验证。

## 端口与分流

| 端口 | 用途 |
|---|---|
| 2101 http / 2100 socks | `general`：ChatGPT / Claude / OpenAI，只放能过地区闸门的节点 |
| 2103 http / 2102 socks | `fast`：Google / GitHub / HuggingFace / 普通网页 |
| 2090 mixed | 命令行（git/pip/curl/npm）：按域名再分流到上面两组 |
| 2086 | Reddit 专用（可选） |
| 2096 | Steam 专用（可选） |
| 8891（或 8892-8900） | 本地 PAC 服务 |
| 9090 | sing-box Clash API（仅本机，供看门狗切换/观测） |

分流规则在 `pacroute.py` 里维护：`general` 域名走 2101，`fast` 域名走 2103，`Kaggle`/国内站点/局域网直连。

## 看门狗与自愈

- **单实例**：启动时读 `watchdog.pid`，若同 PID 文件指向另一个存活的 Python 进程，直接退出，避免双看门狗互相覆盖。
- **端口检查**：60 秒一次；连续失败才触发重建（有 600 秒冷却）。
- **站点闸门**：300 秒一次 ChatGPT / gstatic；连续失败触发重建。
- **PAC 检查**：120 秒一次，对比 `pac_url.txt` 里记录的实际地址，并确认本地 PAC 服务返回的内容与磁盘 `proxy.pac` **逐字节一致**；不一致会重装。
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
