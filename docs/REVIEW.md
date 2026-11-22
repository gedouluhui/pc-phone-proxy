# 代码审查请求（2026-11-23）

这个仓库有两个产物，共用同一套节点池和分流策略：

- **PC 便携版**（`pc/`）：Python + sing-box，TUN 模式接管全局流量，另起 2098 端口做 Google/AI 专用出口。
- **Android App**（`phone/`）：Java + Xray-core，VpnService 建 TUN，节点池内置 8 条 + 支持导入/订阅。

近期为了修「AI 站打不开 / 下载极慢」动了六个提交，**改动集中、但都是线上踩出来的**，希望有人从外部视角审一遍。

## 请重点看这几处

1. **Xray 配置生成的健壮性**（`phone/src/com/luhui/phoneproxy/ConfigBuilder.java`）
   内核是「整份配置要么全用、要么全不用」：任意一条出站不合法，`startLoop` 直接失败，表现为点「启动代理」就报 `启动失败`。已逐个补校验：
   - `SUPPORTED_NET`：拒绝 Xray 26 已移除的 `http` / `h2` 传输；
   - REALITY 只允许 `raw/tcp/xhttp/grpc`，`xtls-rprx-vision` 只允许 raw；
   - SS2022 的 PSK 必须是 16/32 字节 base64。
   **担心的是还有第四、第五种没覆盖**（例如 vmess 的 `aid`/`scy`、trojan 的 alpn、grpc multiMode、xhttp 参数）。有没有更系统的做法：预先拿 Xray 自己校验一遍配置，或者把导入节点逐个用 `Libv2ray.measureOutboundDelay` 探活后再进池？
2. **启动兜底**（`phone/src/com/luhui/phoneproxy/ProxyVpnService.java`）
   `startLoop` 抛错时剔除所有 `i*` 导入节点、只用内置节点重试一次。逻辑是否正确？`controller` 重建是否会有资源泄漏（旧的 controller 没显式 shutdown）？
3. **PC 端 TUN 的 DNS 与路由**（`pc/_proxy/tun_mode.py`）
   - 本机 DNS 对 Google/ChatGPT/HF 是被污染的（解析到 Facebook 的 IP），所以 TUN 自带 DoH：`dns.servers = https(1.1.1.1, detour=gai) + local`，`DOMESTIC` 走 local，其余 `final=doh`，53 端口 `hijack-dns`。
   - **注意 detour 不能指 `grp-any`**：那个组的 urltest 探针要解析域名，会和 DoH 互相等待，导致整机 DNS 超时（真踩过）。
   - 分组按 `node_deep.json` 的 `dl_kbps` 排序（rescan.py 每次扫描写入），慢节点垫后兜底。
4. **节点选择是否合理**
   - `grp-google` 探针用 `gemini.google.com/robots.txt`，`grp-amazon` 用 `aws.amazon.com/robots.txt`——理由是用 gstatic 探测的「最快」节点对目标站可能是最慢的（实测 10 KB/s vs 118 KB/s）。这种「同源探针」的做法有没有更好的替代（比如按连接历史吞吐加权）？
5. **安全**
   - 凭据不进日志：`gen_nodes.py` 只打印 outbound 里的 address/port，不 echo vmess 的 base64 整串；
   - `SubscriptionGuard` 拦本地地址（防 SSRF）；
   - APK 用仓库内 keystore 签名（`PROXY_KEYSTORE` / `PROXY_KS_PASS` 走环境变量）。

## 已知问题（不用重复指出）

- 免费节点池质量差：上行 0.1~0.5 MB/s，10 分钟就能掉一半，配置层到顶了。
- 手机端「测速」按钮只测延迟（`Libv2ray.measureOutboundDelay`），不测吞吐；自动选线的探针已改成 32KB 负载，但还没在真机上长跑验证。
- Google 账号地区/学生认证这条线没做完（缺美国付款资料和卡）。

## 怎么跑

- 单测：`python -m unittest discover -s tests_ci`（78 个，CI 里跑）
- PC：`pc/_proxy/` 下 `python tun_mode.py start`（需要管理员，会建 `pcproxy` 网卡）；诊断 `python doctor.py`
- APK：`phone/` 下 `python build_apk.py`（需要 JDK 17 + Android SDK build-tools；不依赖 Gradle）

## 环境事实

- Windows 11，中文路径；网络环境有 GFW，节点都是免费机场/公开源。
- PC 端 `pcproxy` TUN + `2098` 二级出口是特意设计的：Google 对 gemini/antigravity 有独立的地区/IP 判定，必须单独挑出口。
