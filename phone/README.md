# 手机端：构建说明

一个自研的 Android 代理 App（包名 `com.luhui.phoneproxy`），Java 外壳 + Xray 内核。
不需要 Gradle，`build_apk.py` 直接调用 JDK / Android SDK 命令行工具完成构建。

## 源清单实测 + 可远程更新 + 协议均衡取样（v3.2，2026-11-23）

- **源清单逐条实测**：在用户的大陆网络下拉取了 39 个候选源。删掉 404 的 `aiboboxx/v2`、`mfuu`，
  删掉与 peasoft 内容完全相同的 `chengaopan`；新增 `tony163`（自称湖北移动测速后上传）、
  `Barabama/clashmeta.txt`（约 1800 条，含 166 条 hysteria2）、`free18`。实测时 peasoft 61 条、
  ermaozi 68 条、barry Sub1 47 条 hysteria2，v3.1 加的 Hysteria2 支持在这些源上直接生效。
- **远程源清单**：`phone/sources.json` 放在仓库里，App 补充节点时先经 jsDelivr / ghfast / raw 取这份清单
  （≥3 条合法条目才采用；只接受 https 的 GitHub raw / jsDelivr / gist 地址），取不到才用 APK 内置表。
  以后源失效只要改仓库里的 JSON，不用重新发 APK（jsDelivr 缓存最长约 12 小时）。
- **协议均衡取样**：每个源按协议分桶轮流取候选（`interleaveBySchema`），大聚合源前几百条全是 vless 时
  Hysteria2 也能被抽到；Hysteria2 候选每次最多 48 个（不能 TCP 预筛，死节点要等内核超时）。
  内核实测线程 8 → 12。

## 带宽感知选线 / Hysteria2 / SNI 分片自救 / 自动 AI 闸门（v3.1，2026-11-23）

v3.0 解决了「能不能连上」，v3.1 解决「连上之后快不快、稳不稳」：

- **带宽感知选线**：`NodeTester.speedTest` 用内核对实测最快的节点下载 256 KB（移动数据 128 KB）。
  libv2ray 的 `measureInstDelay` 会读完响应体再计时、两次取快（第二次复用连接），所以
  「下载耗时 − 204 延迟」≈ 纯传输时间。评分 = 延迟 + 200000/带宽(KB/s)（≈ 加载一个 200 KB 资源的毫秒数），
  `aliveFresh` / 运行配置 / 兜底出口都按评分排。
- **内核选路**：`observatory + leastPing` → `burstObservatory + leastLoad`。burst 每个节点保留最近 3 次探测
  （3 分钟一轮），leastLoad 比较「平均延迟 + 抖动」× 代价系数；系数 = 评分/延迟（限制 1~20），
  用锚定正则 `^tag$` 写进 `costs`（非正则是子串匹配，`proxy-i1` 会误伤 `proxy-i10`）。
  `expected=1` 让出口固定、不随机换 IP；`maxRTT 5s`、`tolerance 0.34`（3 次里失败 2 次就不选）。
- **何时测带宽**：连上 8 秒后后台测一次；之后每 20 分钟维护时补测 2 小时内没测过的。
  测完若发现评分好 1.8 倍以上的节点才重建出口（断流 1~2 秒），否则等下次重建自然生效。
- **Hysteria2**：解析 `hysteria2://` / `hy2://` → `protocol=hysteria`（version 2）+ `network=hysteria`
  + 强制 TLS（ALPN h3）；`obfs=salamander` → `finalmask.udp`；`443,20000-30000` 或 `mport=` →
  `finalmask.quicParams.udpHop`。UDP 节点跳过 TCP 预筛直接内核测。`insecure=1` / `pinSHA256` 不采纳
  （与其它导入节点一致，自签名节点在实测阶段被筛掉）。
- **SNI 分片自救**：普通 TLS 节点（非 REALITY/QUIC）TCP 能连上、TLS 却不通时，用 ClientHello 分片
  （`finalmask.tcp` fragment，`tlshello` / 长度 100-200 / 间隔 10-20ms）重试；通了就记到 `NodeHealth.frag`，
  `ConfigBuilder.loadNodes` 之后对该节点一律套上分片。下拉标签显示「分片」。
- **自动 AI 闸门**：连上后如果当前出口里一个 AI 合格节点都没有，每天自动跑一次（12 个节点），
  验出合格节点就重建出口；维护线程也会在发现新的 AI 合格节点时重建。
- 界面：节点标签多了实测带宽（如 `· 320ms · 1.2MB/s`）。
- 验证：投毒语料 351 条（+18 Hysteria2、+1 分片出站），154 条被接受、全部过 `xray run -test`；
  `full_auto` 改走 leastLoad + costs + fallback，golden 由新增的 `Poison golden` 工作流在云端重新生成。

## 本机实测选线与节点池自维护（v3.0，2026-11-23）

**问题**（实机截图）：「已连接 · 自动选线（144 节点池）」，但 144 个节点全部「不可用」，网页图片都打不开。
三个根因：① 内置 24 个节点是电脑端 **TUN 开着**跑深测得到的——深测子进程被 TUN 接管、经当前出口二次转发，
测的是「境外能连」而不是「大陆直连能连」；② 公开源按顺序凑满 120 条就停，前三个伊朗/全球向的源占满名额，
面向大陆的源轮不到，且入池前从不测连通性；③ 内核里放全部节点、observatory 10 分钟一轮、无兜底出口，
全死时仍显示「已连接」。

**做法**：

- `NodeTester`：**在手机上直连实测**（App 自身不走 VPN）。TCP 预筛（3s、32 并发）→ 通过的用
  `measureOutboundDelay` 真发 `generate_204`（8 并发）。结果按节点指纹存进 `NodeHealth`，30 分钟内算新鲜。
- `NodePool`：公开源 12 个（大陆向在前），每个自动试 raw → jsDelivr → ghfast.top，6 路并发、全部抓完，
  去重后最多 480 个候选，**实测能连上的才入池**（上限 80）；连续失败 3 次的导入节点自动删除。
- `ProxyVpnService`：可用 <6 先实测（够 6 个先连）；全灭自动去公开源找；仍然没有就**报错、不建 VPN**。
  运行配置只放实测可用的最快 30 个，balancer 设 `fallbackTag`=最快节点；observatory 改 `generate_204/180s`。
  运行中每 20 分钟后台复测、清死节点、可用 <5 自动补充，出口过半失效自动重建内核。
- 界面：下拉按实测排序并显示 `xxms / 未测 / 不可用`；新增「清理不可用的导入节点」；空池可直接点启动。

**电脑端配套**：`pc/_proxy/tun_mode.py` 路由第一条让 `sing-box.exe` / `xray.exe` 直连，TUN 开着扫描也能测出真实结果。
重新生成内置池：TUN 重启 → 重新扫描节点 → `gen_pool.py` → `build_apk.py`。

**验证状态**：GitHub Actions CI 全绿（`javac`、`check_poison.py` 投毒闭环 + golden、完整打包、`tests_ci`）；
签名 APK 由新增的 `.github/workflows/phone-apk.yml`（手动触发，仓库 secret `PHONE_KS_B64` / `PHONE_KS_PASS`
= 本地 `phoneproxy.keystore`）构建，证书与 v2.x 一致可覆盖安装，已挂到 Release v3.0。**尚未真机验证**，
按 `kaggle/PHONEPROXY_V3_HANDOVER_2026-11-23.md` 的清单验收。

## 内核预检与投毒闭环（v2.6）

**问题**：`parseUri` 的规则和 Xray 内核是两套实现，解析器放过的配置不一定能启动；
一条坏节点被塞进同一个 `outbounds` 数组，内核会拒绝整份配置，表现就是「启动失败」。

**做法**：解析器抽成纯 JVM 的 `NodeConfigCodec`（不依赖 Android Framework），
再用 AAR 已暴露的 `Libv2ray.measureOutboundDelay` 做**零网络**内核预检：

- 把待测 outbound 拼成最小配置，探测 URL 故意写成 `http://[::1`；
- `http.NewRequest` 在拨号前就失败，所以整个调用不会发任何流量；
- 只有 `config load error` / `instance creation failed` / `startup failed` 判为配置无效，
  URL 错误说明配置已经被内核接受；
- 导入时逐条预检（`screenImports`），启动被内核拒绝时后台标记坏节点
  （`quarantineInvalidImports`），下次启动直接跳过；缓存键是 outbound JSON 的 SHA-1，
  解析规则一变就自然失效。

**投毒语料**：`phone/tests/PoisonHarness.java` 生成 333 条样本（正常链接 + 变异/畸形/
私网地址/超长/错误编码），`phone/tools/check_poison.py` 编译纯 JVM 解析器后：
每条被接受的 outbound 和 auto/manual 完整配置都交给真 `xray run -test`，
完整配置还与 `phone/tests/full_config.golden.json` 逐字节比对。CI 的 `android` job
已接入（固定版本 + SHA256 + 缓存），任何解析规则与内核漂移都会直接失败。

## AI 出口闸门（v2.5）

**问题**：公开源导入的节点没有任何「地区资格」信息。App 原来的 `cg-balancer` 只认
内置 `assets/nodes.json` 里的 `cg` 标记（由电脑端深测写入），所以公版用户 100% 走普通
balancer，ChatGPT / Claude 被 Cloudflare 判「不支持地区」→ 403，而用户只看到「能上网但
AI 打不开」。

**做法**：新增 `ACTION_GATE` 与界面上的「AI 闸门」按钮。对**延迟最快的 24 个节点**，
用 `Libv2ray.measureOutboundDelay` 各打两个探针：

| 探针 | 判据 |
|---|---|
| `https://chatgpt.com/cdn-cgi/trace` | 200/204 |
| `https://claude.ai/cdn-cgi/trace` | 200/204 |

`libv2ray` 内部的 `measureInstDelay` **只把 200 / 204 认作成功**（其它状态码返回 -1），
所以地区封锁的 403 会被正确判失败——这不是「ping 得通就算过」。两个都过才写进
`SharedPreferences` 的白名单，`loadNodes()` 把它并进 `Node.cg`，AI 域名规则只挂
`cg-balancer`。

几个刻意的取舍：

- **按节点指纹存，不按 tag**：导入节点的 tag 是 `i0/i1…` 按位置生成的，换一次源整批平移，
  用 tag 会把「能过闸门」的标记贴到别的节点上。指纹是 `server:port/protocol` 的 SHA-1 前 8 字节。
- **结果 1 天过期**：免费节点换手快，两周前的结论比没有结论更误导。
- **只验最快的 24 个**：120 个节点 × 2 探针 × 12s 超时会把手机烤熟；慢节点本来也抢不到流量。
- **开代理时如果 `cg` 池为空会明确提示**，不再静默降级（原来这是最坑的一点）。
- **不自动跑**：测一次是分钟级的耗电动作，交给用户按需点；导入后日志会提示。

手动验证：连上代理 → 点「AI 闸门」→ 等 1-2 分钟 → 日志给出「合格 N/24」，
节点列表里通过的打 `AI✓`。

## 环境

| 依赖 | 说明 |
|---|---|
| JDK 17 | 设置 `JAVA_HOME`，或改脚本里的 `find_jdk()` |
| Android SDK | 需要 build-tools（含 d8/aapt2/zipalign/apksigner）和一个 `android-35` platform；设置 `ANDROID_HOME` / `ANDROID_SDK_ROOT` |
| AndroidLibXrayLite | 下载 `libv2ray.aar` 放到 `phone/libs/libv2ray.aar` |
| Python 3.8+ | 仅用于运行构建脚本 |

`libv2ray.aar` 下载地址：<https://github.com/2dust/AndroidLibXrayLite/releases>
（选与 Xray-core v26.x 对应的版本；本项目验证过 v26.10.31 / Lib v40。）
脚本优先使用已有的 `phone/libs/xray/classes.jar` 及同目录资源，否则把 AAR 解压到本次构建的独立临时目录；构建需要四个 ABI 的 `libgojni.so` 以及 `geoip.dat` / `geosite.dat`。

## 构建

```bash
cd phone
python build_apk.py
```

非正式构建默认使用 `phone/phoneproxy.keystore`（演示口令 `android`，别名 `phoneproxy`，仅用于本地测试）；
文件不存在时才自动生成。可用 `PROXY_KEYSTORE`、`PROXY_KS_ALIAS`、`PROXY_KS_PASS` 指定签名配置；
keytool 与 apksigner 共用别名和口令，口令通过工具的环境变量通道传递，不写入命令参数。

正式构建设置 `PROXY_RELEASE=1`（兼容旧别名 `PROXY_RELEASE_BUILD=1`；任一变量非空即启用，`0` 也不表示关闭）。
此模式自动启用公开输入检查，并要求显式配置已存在的 `PROXY_KEYSTORE` 和非空、非演示口令的 `PROXY_KS_PASS`，
绝不自动生成密钥。`--public` 本身仅启用公开节点检查，不等同于正式签名模式。

产物默认是 `phone/手机代理.apk`，可用 `PROXY_APK_OUT` 改输出路径；各路径变量的相对路径均相对于 `phone/`。
每次构建使用独立临时目录，签名验证和节点资源检查均通过后才原子替换最终 APK；替换成功是提交点，提交前失败不覆盖已有产物。
提交后若暂存清理失败（例如 Windows 文件占用），仍返回成功码，并提示“产物已验证并晋升，但暂存清理失败”；不回滚或再次覆盖最终 APK，解除占用后需自行清理残留暂存目录。
节点 ZIP 条目仅接受本构建使用的普通 STORED/DEFLATED 格式，校验局部头/中央目录一致、真实展开长度、CRC 和压缩流完整性，展开最多读取 1 MiB + 1 字节并拒绝超过 1 MiB 的资源；加密、数据描述符及 ZIP64 节点条目不支持并拒绝。

> 只要沿用同一个 keystore，本地构建的私用版与 Release 公版**签名一致**，可直接覆盖安装。
> 若首次构建自动生成了新 keystore，签名就不同，覆盖安装会报“应用未安装”，需先卸载旧版。
> keystore 被 `.gitignore` 忽略，换机器构建时要把同一个文件带过去。

### 内置自己的节点

App 支持三种节点来源：

1. **公开源一键导入**（v2.4 起，公版也能用；v3.0 起 12 个源、本机实测后只留能连上的）：APK 里只存公开聚合列表的 URL
   （`ConfigBuilder.PUBLIC_SOURCES`，每个都有 GitHub raw + jsDelivr 镜像），运行时抓取、去重、限 120 条，再自动测速。
   **不含任何节点凭据**，所以公开版装完点一下就能用。
2. **用户导入**：粘贴分享链接或订阅地址。
3. **安装包内置**（`assets/nodes.json`）：只用于自用版。公共版不内置任何节点；要做一个只给自己用的版本：

> **公开构建使用 `--public`，正式发布还需启用 `PROXY_RELEASE=1` 并配置正式签名。**
> `--public` 不再静默替换为强制空表：所选输入必须恰为 JSON 空数组 `[]`，非空或无效输入
> 会在工具发现、编译和签名前被拒绝。默认优先选本地 `assets/nodes.json`，仅当它不存在时
> 才回退到 `assets/nodes.sample.json`；本地池非空时应显式设置
> `PROXY_NODES_JSON=assets/nodes.sample.json`，不必修改或删除本地池。
> 显式指定的文件缺失也会失败，不再回退。最终公开 APK 必须含唯一的 `assets/nodes.json=[]`。
> 未启用公开或正式模式时，所选非空节点会打进私用 APK，禁止公开发布。

```bash
# 方式 A：从电脑端 pinned.json（分享链接 -> outbound）
python gen_nodes.py /path/to/pinned.json

# 方式 B：从电脑端深测结果挑一批（目标 24 个，可用不足时自动收缩；推荐，保留原始分享链接）
PROXY_DIR=/path/to/代理便携版/_proxy python gen_pool.py

python build_apk.py
```

`assets/nodes.json` 已被 `.gitignore` 忽略，**不要把它提交到公开仓库**。

### ⚠️ 打包前检查清单（v2.1 踩过的坑）

`build_apk.py` 把预检后的所选节点快照打入 APK，不会在打包时重新读取可能变化的输入。
仓库提交的是空的 `assets/nodes.sample.json`；本地生成的 `assets/nodes.json` 被忽略。
**公开 APK 的节点资源必须为 `[]`：装到手机上会先提示「还没有节点」，
用户点「导入节点 / 订阅 → 从公开源导入」即可（v2.4 起），或粘贴自己的订阅。**

以下是 Bash 命令（在 `phone/` 下执行）。上传 Release 前须已通过环境变量配置既有正式 keystore 和口令；
私用构建则须取消 `PROXY_RELEASE` 和 `PROXY_RELEASE_BUILD`，并确认没有遗留的 `PROXY_NODES_JSON` 覆盖本地池。

| 要产出的东西 | 命令 | 检查 |
|---|---|---|
| 空节点本地测试版 | `PROXY_NODES_JSON=assets/nodes.sample.json python build_apk.py --public` | 非正式模式；不得代替正式签名 |
| 公版（上传 Release） | `PROXY_RELEASE=1 PROXY_NODES_JSON=assets/nodes.sample.json python build_apk.py --public` | 正式签名；APK 内唯一 `assets/nodes.json` = `[]` |
| 私用版（自己装） | `python gen_pool.py` 后再 `python build_apk.py` | APK 内节点与所选本地池一致，禁止公开发布 |

> v2.4 的公版即使节点池为空也能用：用户在 App 里点「从公开源导入」即可，不必再自建私用版。

打包后对实际待发布文件运行 `python check_release.py <apk>`，确认检查通过后再发布。
显式指定的 APK 必须存在且有效，缺失、重复、超大或无效节点资源以及非空数组都会返回非零；
无参数时检查 git 清单及存在的默认产物，不存在的默认产物会跳过。
**不要把含节点的 APK 传上 Release**；空节点公版现在是可用的（用户点公开源导入），
但想让家里人"装完什么都不用点"，仍然要给他们内置节点的私用版。

自动化检查（审查 C10）：

```bash
python check_release.py                        # git 里有没有凭据/keystore/APK
python check_release.py ../dist/手机代理-公版.apk  # APK 内嵌了几个节点
```

`git ls-files` 里有 `nodes.json` / `*.keystore` / `*.apk` 时脚本返回非零，先 `git rm --cached` 再发布。

节点列表格式（App 也接受 `uri` 字段，直接用原始分享链接）：

```json
[
  {
    "tag": "p0",
    "name": "NL vless 3.2M GPT",
    "uri": "vless://YOUR-UUID@example.com:443?security=reality&...#example",
    "cg": true
  }
]
```

`cg=true` 表示该节点通过了 ChatGPT 地区闸门，会被放进 `cg-balancer`（OpenAI/Anthropic 域优先）。
`outbound` 字段也可以直接写完整的 Xray outbound 对象，优先级高于 `uri`。

## 代码结构

| 文件 | 作用 |
|---|---|
| `src/.../MainActivity.java` | 界面：一键启动/断开、节点下拉、测速、导入/订阅、日志、流量显示 |
| `src/.../ProxyVpnService.java` | 前台 VPN 服务：建 TUN、启动/停止 Xray、统计流量、通知 |
| `src/.../NodeConfigCodec.java` | 纯 JVM 解析器 + 完整 Xray 配置生成（可脱离 Android 测试） |
| `src/.../ConfigBuilder.java` | Android 胶水：Context/偏好/网络/内核预检，委托 `NodeConfigCodec` 生成配置 |
| `src/.../NodeHealth.java` | v3.0：本机实测健康度（按节点指纹持久化） |
| `src/.../NodeTester.java` | v3.0：TCP 预筛 + 内核真实请求的两段式实测 |
| `src/.../NodePool.java` | v3.0：导入池唯一写入口；公开源补充、死节点清理、运行配置选员；v3.1：综合评分与 leastLoad 代价系数 |
| `tests/PoisonHarness.java` | 333 条投毒语料生成器，输出每条被接受的 outbound 与完整配置 |
| `tools/check_poison.py` | 编译并运行投毒语料，逐条过 `xray run -test`，比对 golden |
| `AndroidManifest.xml` | minSdk 24 / targetSdk 33，VPN Service 声明 |
| `build_apk.py` | javac → d8 → aapt2 → zip → zipalign → apksigner |
| `gen_nodes.py` / `gen_pool.py` | 把电脑端节点数据转换/挑选成 `assets/nodes.json` |

## 实现要点

- **分流**：`geosite:cn`、`geoip:cn`、`geoip:private` 走 `direct`；其余走 `proxy`。
- **自动选线**（v3.1 起改为 burstObservatory + leastLoad + 带宽代价系数，详见上文；v3.0 时）：内核只放本机实测可用的最快 30 个节点；Xray `observatory` 每 3 分钟用 `generate_204` 探测，
  `balancer`（leastPing）按探测结果选路，`fallbackTag` 兜底到实测最快节点。以下是 v2.x 旧设计的记录：
  observatory 每 10 分钟探测一次，`balancer` 按探测结果选路，节点失败自动切换。
  探针是 16KB 的固定负载（`speed.cloudflare.com/__down?bytes=16384`）而不是 `gstatic/generate_204`：
  0 字节响应只反映握手延迟，测不出带宽，PC 端实测同一批节点上行 547 / 435 / 128 KB/s、握手延迟却几乎一样，
  leastPing 就会稳定选中较慢那颗（页面能开、传大文件传不动）。16KB 在 128 KB/s 上要 125ms、在 547 KB/s 上约 29ms，
  延迟里仍能带上吞吐；8 节点约 18MB/天，比 32KB/5 分钟省 75%。
- **ChatGPT**：通过 `cg=true` 的节点组成 `cg-balancer`，只给 OpenAI/Anthropic 域名使用。
- **防回环**：VPN 建立时 `addDisallowedApplication(自身包名)`，App 自己的流量不走 TUN。
- **订阅传输**：只接受 HTTPS；每个 URL 每跳只解析一次并校验全部 A/AAAA，随后固定连接到已验证 IP，同时保留原域名 SNI/Host 和证书主机名校验。拒绝私网/保留地址、HTTPS 降级、超过 3 次重定向或超过 2 MiB 的响应；不使用环境代理或明文 HTTP 回退。
- **DNS**：国内 `223.5.5.5` 直连解析；国外域名走 Cloudflare DoH（经代理）。
- **导入**：分享链接逐条解析，失败的单条跳过并写日志；订阅地址下载后按行解析（body 无 `://` 时按 base64 解）。
  解析阶段会拒绝 Xray 26 已移除的传输（`http` / `h2`）以及 REALITY 不支持的组合
  （`reality` 只能配 `raw`/`xhttp`/`grpc`，`xtls-rprx-vision` 只能跑在 raw 上）：
  这类节点留在池里会让整份配置解析失败，一条坏链接把整池拖死（实机表现是点「启动代理」直接 `启动失败`）。
  shadowsocks-2022 的 PSK 也在这里验（必须是定长 base64：aes-128 16 字节、aes-256/chacha 32 字节）。
  万一还有漏网的，`ProxyVpnService` 会在内核拒绝配置时剔除全部导入节点、只用内置节点重启一次。
- **公开源**（v3.0）：12 个聚合列表 6 路并发全部抓取，每个依次试 raw / jsDelivr / ghfast.top；按 server:port/协议去重，
  最多 480 个候选，**本机实测能连上的才入池**（上限 80）。v2.x 是依次抓、凑满 120 条就停、不测连通性。
- **空池 / 全灭保护**（v3.0）：节点池为空或全部不可用时，启动会自动去公开源找节点；仍然没有就报错、不建立 VPN。

## 许可

App 使用 MIT；Xray-core（MPL-2.0）、AndroidLibXrayLite（LGPL-3.0）等第三方组件见仓库根目录 `THIRD_PARTY_NOTICES.md`。
