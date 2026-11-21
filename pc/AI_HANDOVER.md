# 代理便携版 V3.2 —— 交接说明

给下一个接手的人（或 AI）。**先读「当前必读」，再动手改代码。**

---

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
- **Google AI 专用出口 2098**：Google 按出口 IP 判定地区，同一批节点里有的被
  拒（notebooklm 返回 `location=unsupported`）。2098 用 `pinned.json` 里除
  `google_bad.json` 之外的节点组成 urltest 组，AI 域名优先走它。

提交：`0035ed5` → `48e0bc3` → `7b9161c` → `fc43f9c` → `954272c`。

---

## 二、入口与目录

```
代理便携版\
  启动代理.bat      选择模式并启动（1 分流 / 2 TUN）
  关闭代理.bat      完整关闭：进程、PAC、静态代理、环境变量、直连实测
  体检.bat          六层体检，第一个 FAIL 就是根因
  修复AI出口.bat    只重建 2098，不动隧道（AI 站点打不开先点它）
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
| 2098 | Google AI 专用出口（urltest，多节点自动切换） |
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
4. AI 站点打不开 → 先点 `修复AI出口.bat`（只换 2098，不断网）。
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
