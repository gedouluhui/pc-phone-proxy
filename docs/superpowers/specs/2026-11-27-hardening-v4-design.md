# pc-phone-proxy hardening/v4 设计

日期：2026-11-27  
基线：`69d0114fa52f12edca009f06db7c4ed07c83f900`  
范围：审计报告的 P0、P1 与 Windows/Android 产品化。服务端、计费、客服、法律牌照、真实节点运营不在本设计内。

## 1. 目标与约束

### 1.1 目标

1. 消除本机提权、SSRF、进程误杀、无鉴权控制面、AI 路由静默降级等高风险问题。
2. 让自动换池、重扫、配置提交遵循“无证据不切换、失败可回滚、单写入者”。
3. 统一双端路由与节点身份，避免 Wi-Fi/蜂窝和不同凭据之间张冠李戴。
4. 将 Windows 从脚本栈升级为可安装、可更新、有托盘状态界面的产品；将 Android 升级到 target API 36，并补暗色、无障碍、取消、订阅和每应用代理。
5. 让 CI 验证二进制哈希、源清单签名、APK 16 KB 对齐、真实内核配置和发布完整性。

### 1.2 约束

- 保留 sing-box 与 Xray-core，不重写协议栈。
- 不修改用户当前运行的 `Desktop/代理便携版`，不热替换正在运行的 TUN。
- 不提交节点 URI、订阅地址、keystore、密码、令牌或真实用户诊断数据。
- 不 force push；开发在 `hardening/v4`，验证后快进 `main`。
- 没有代码签名证书时，CI 可以产出未签名开发包，但发布作业必须失败，不得生成“正式”假产物。
- 真机 VPN 流量、真实运营商矩阵、Windows TUN 实机断网测试保留为人工验收；未完成不得声称通过。

## 2. 方案选择

### 方案 A：在现有 Python/Java 栈内做边界重构（采用）

新增小而独立的模块，替换危险调用点；保留现有脚本入口和内核。优点是迁移风险低、可逐批验证、对运行中网络影响小；缺点是仍保留 Python 运行时，需要安装器解决权限边界。

### 方案 B：推倒重写为单一 Rust/Go 核心 + 原生 UI

长期一致性最好，但会重做协议适配、Windows TUN、Android JNI、发布和测试，周期与回归风险过高，本阶段不采用。

### 方案 C：只修 P0，不做产品化

能最快止损，但无法解决双端策略漂移、交付信任和日常使用体验，不满足本轮范围。

## 3. 总体架构

```text
shared/routing-policy.json
        │
        ├── tools/sync_policy.py ──> pc/_proxy/policy.py
        │                           phone/assets/routing-policy.json
        │
Windows UI / broker / Python core
        │
        ├── process_identity.py
        ├── control_secret.py
        ├── config_transaction.py
        ├── source_fetch.py
        ├── quality.py
        └── sing-box / PAC / WinINET

Android UI / VpnService
        │
        ├── SecureStore.java
        ├── ValidatedHttp.java
        ├── SourceManifest.java
        ├── NodeConfigCodec.java
        ├── NodePool / NodeHealth / NodeTester
        └── Xray-core / TUN
```

### 3.1 单一策略源

`shared/routing-policy.json` 是双端路由策略的唯一真源，包含：

- `domestic`：国内直连域名。
- `sensitive`：银行、支付、政务、教育等强制直连域名。
- `direct`：驱动、系统更新、Kaggle 等强制直连域名。
- `ai`：OpenAI/Anthropic 的专用路由域名。
- `google_ai`：Google AI 专用路由域名。
- `udp`：QUIC/WebRTC/其他 UDP 的默认动作。
- `dns`：国内 DNS、国外 DoH、DoT 与 IPv6 策略。

`tools/sync_policy.py` 生成 PC Python 常量与 Android 资产；CI 执行 `--check`，生成物漂移即失败。PAC、sing-box TUN、Xray 配置和测试都消费同一份策略。

### 3.2 节点身份

节点身份改为“去掉 tag 的规范化完整 outbound 的 SHA-256”。展示名、tag、健康度、AI 闸门和去重都使用该身份。PC 不再只按 host 去重；Android 不再只按 `server:port/protocol` 去重。健康记录增加网络类型与网络指纹，网络变化后旧结论不再直接复用。

## 4. Windows 可信核心

### 4.1 进程身份

新增 `pc/_proxy/process_identity.py`：

- 记录 PID、进程创建时间、可执行文件完整路径与 SHA-256、命令行、用户 SID、配置哈希。
- 提供 `record()`、`matches()`、`terminate_if_owned()`。
- 无法证明所有权时返回 `unknown`，调用方必须拒绝终止，不得退化为按镜像名或端口杀进程。
- 所有现有终止路径统一迁移：`deep_test.py`、`proxyctl.py`、`stop_proxy.py`、`pacroute.py`、`tun_mode.py`、`tun_supervisor.py`。

测试使用合成进程记录、PID 复用、命令行为空、路径变化、哈希变化和无关 sing-box 诱饵。

### 4.2 本机控制面鉴权

新增 `pc/_proxy/control_secret.py`：

- 每个安装生成 32 字节以上随机 secret。
- 使用 Windows DPAPI 加密保存到 `%LOCALAPPDATA%\\PhoneProxy\\control-secret.bin`，并设置仅当前用户可访问的 ACL。
- sing-box Clash API 配置写入 `secret`；所有 Python 客户端统一通过 `control_api.py` 添加 `Authorization: Bearer`。
- 无 secret、鉴权失败或返回非预期状态时，视为控制面不可用，不得继续切换或重建。
- 实现使用 32 字节随机 secret、用户级 DPAPI 加应用熵、仅当前用户的 ACL；密文损坏或无法解密时拒绝启动且不自动覆盖。控制客户端只允许 loopback HTTP，禁用环境代理与重定向，防止令牌被转发到其他地址。

### 4.3 配置事务

新增 `pc/_proxy/config_transaction.py`，统一 split/TUN 的提交协议：

1. 在单一命名互斥锁内生成 `.new` 配置。
2. 执行真实 `sing-box check`。
3. 保留上一份已知可用配置与节点池。
4. 启动候选、执行真实验收。
5. 成功后原子替换正式配置；失败恢复上一份并记录原因。
6. 提交成功后清理临时文件；清理失败不得回滚已提交状态。

`bestroute.py` 与 `tun_mode.py` 不再各自实现“先覆盖/先停后建”。旧节点只能沿用带时间戳的真实测量值，删除伪造的 `dl=400/ul=120/github_ok=True/chatgpt_ok=True`。

### 4.4 fail-closed 闸门

- `pool_switch_ok({})` 在普通模式下返回 `False`。
- 紧急恢复模式必须显式传入，且只允许使用上一份已知可用配置。
- `switch_min_live(prev_live)` 使用当前真实健康数，不再封顶到 3。
- TUN 开着时，直连 SOCKS 不可用或污染探测结果未知，禁止重扫。
- post-switch 未知默认回滚；只有独立证明物理网络断开时才保留新配置。
- 测试反向断言空字典、异常、超时、未知都不得放行。

### 4.5 受限源抓取

新增 `pc/_proxy/source_fetch.py`：

- 流式读取，单源与总响应大小上限。
- 手工重定向，每跳校验 scheme、host 与解析后的 IP。
- 拒绝回环、私网、链路本地、CGNAT、多播、保留地址和 IPv4-mapped IPv6。
- 记录内容哈希与来源，不记录订阅 token。
- 公共节点剥离或拒绝 `insecure=1`；用户自有节点需要逐条显式允许。

### 4.6 提权 broker 与便携模式

安装模式：

- broker 代码与嵌入 Python 安装到 `%ProgramFiles%\\PhoneProxy`，普通用户不可写。
- 计划任务动作固定为 broker，参数只含用户配置目录；broker 校验自身安装清单哈希与 ACL。
- 用户配置放 `%LOCALAPPDATA%\\PhoneProxy`，敏感字段 DPAPI 加密。
- TUN 启动、停止、守护都经 broker；非提权 UI 不执行提权代码。

便携模式：

- 保留免安装 split 模式。
- 不再注册提权计划任务；TUN 提示使用安装版。
- 旧版本已注册的 `PhoneProxyTunGuard` 在升级/卸载时由安装器核验动作后删除。

### 4.7 Windows 产品壳

新增 `pc/app/`：

- Python/Win32 托盘图标与状态窗口，显示连接状态、当前模式、健康出口数、最近错误。
- 操作：连接、断开、切换 TUN/split、体检、打开诊断、退出。
- 不显示节点凭据；日志默认脱敏。
- 新增 Inno Setup 安装脚本，安装 broker、sing-box、wintun、Python 与快捷方式；卸载时停止服务并恢复系统状态。
- 自动更新使用签名 `release-manifest.json`，校验签名与 SHA-256 后启动安装包；失败保留旧版本。

## 5. Android 可信核心

### 5.1 DNS 重绑定修复

新增 `ValidatedHttp.java`：

- 对每个 URL 只解析一次，校验全部 A/AAAA。
- 使用受控 `SSLSocketFactory` 连接到已验证 IP，SNI 与主机名验证仍使用原域名。
- 每跳重定向重新执行解析、校验与连接。
- 不允许 HTTPS 降级到 HTTP；HTTP 订阅默认拒绝，只有用户显式开启“允许不安全 HTTP”才可用。
- 测试用本地 DNS 服务器交替返回公网/私网地址，验证不会连接私网。

### 5.2 源清单签名

`phone/sources.json` 增加版本与发布元数据，新增 `SourceManifest.java`：

- APK 内嵌项目公钥。
- 运行时拉取清单与签名，验证 RSA/SHA-256 签名、版本单调与 schema。
- 第三方镜像只提供可用性，不提供信任；签名失败则回退 APK 内置清单。
- CI 在改动清单时重新签名并验证；私钥存 GitHub secret，不进仓库。

### 5.3 AI 路由

`NodeConfigCodec.fullConfig()`：

- `cg-balancer` 只能兜底到 AI 合格节点。
- 没有 AI 合格节点时，AI 域名走 blackhole 并显示明确原因。
- 固定非 AI 节点时，AI 域名默认阻断；用户可在设置中显式允许未验证 AI 出口。
- 增加冷启动、观测无数据、AI 全灭、普通兜底不属于 AI 池的回归。

### 5.4 凭据存储

新增 `SecureStore.java`：

- 使用 Android Keystore AES/GCM 加密导入 URI 与订阅 URL。
- 首次启动迁移旧 SharedPreferences 明文数据，迁移成功后删除旧键。
- 日志与 UI 只显示脱敏节点名，不输出完整 URI。
- 备份与设备迁移规则继续排除所有应用数据。

### 5.5 生命周期与取消

- `ProxyVpnService` 引入会话代号、`stopRequested` 与独立停止通道。
- `NodeTester` 接受取消信号，超时后 `shutdownNow()`，不再在线程仍运行时触发完成回调。
- 启动、测速、闸门、订阅抓取全部可取消；停止优先于排队任务。
- 网络回调增加 `onLost`/`onCapabilitiesChanged` 去抖，清理旧网络健康度并重建或重绑内核。
- 核心死亡检测与自动恢复；提供 always-on/“无 VPN 禁止联网”的用户引导。

### 5.6 Android 产品化

- target SDK 36，compile SDK 36；CI 安装对应 platform。
- 资源化布局与主题：暗色、大字、TalkBack 标签、足够触控面积、横屏/平板。
- 节点页支持搜索、协议筛选、收藏、固定/自动、取消操作。
- 订阅页支持新增、更新、启停、删除与来源展示。
- 每应用代理选择；路由策略只读诊断与导出。
- 诊断页包含 DNS/IPv6/WebRTC 检查、kill-switch 引导、脱敏日志导出。
- APK 构建固定 `zipalign -c -P 16 4`，CI 验证 arm64/x86_64 ELF 与 ZIP 对齐。

## 6. CI、发布与供应链

- GitHub Actions 固定到 commit SHA，权限最小化。
- sing-box 与 AAR 下载后校验 SHA-256；Xray 与 org.json 沿用现有哈希机制。
- 新增 `tools/verify_sources.py`，CI 验证源清单签名。
- 新增策略同步检查、秘密扫描、SBOM 与构建来源证明。
- 合并为一条可复用发布流水线，统一 secret 名称与 release 预检。
- Android 正式发布要求 keystore、非演示口令、签名验证、16 KB 对齐、空节点池。
- Windows 正式发布要求代码签名证书；缺失时构建开发产物但禁止发布。
- 发布 `release-manifest.json` 包含版本、提交、文件名、大小、SHA-256 与签名。

## 7. 数据流与错误处理

### 7.1 自动换池

```text
候选测量 → 完整结论？ ─否→ 保留当前隧道
            │是
健康数不低于当前？ ─否→ 拒绝并恢复上一份节点池
            │是
生成 .new → sing-box check → 启动候选 → 真实验收
            │失败
回滚上一份已知可用配置并记录
```

### 7.2 Android 启动

```text
读取加密节点 → 网络指纹匹配的新鲜健康度
            │不足
可取消地本机实测 → 足够则继续，全灭则找源
            │仍全灭
不建立 VPN，显示可行动错误
```

### 7.3 订阅抓取

```text
URL 校验 → 单次 DNS 解析并校验 → 连接到已验证 IP
       → 每跳重定向重复上述过程 → 大小上限 → 签名/schema 校验 → 解析节点
```

任何一步失败都不静默降级为不安全路径。

## 8. 测试与验收

### 8.1 自动化

- 每个新模块先写失败测试，再实现。
- 关键闸门做变异测试：把 fail-closed 改回 fail-open 必须翻红。
- 进程身份测试覆盖 PID 复用、空命令行、错误路径、错误哈希、无关进程诱饵。
- DNS 测试覆盖公网/私网交替答案、重定向、HTTPS 降级、IPv4-mapped IPv6。
- 源清单测试覆盖签名缺失、篡改、旧版本回放、schema 错误。
- Android 配置测试覆盖 AI 兜底、固定非 AI 节点、冷启动。
- 回归：现有 133 项、351 条投毒、真实 sing-box/Xray 配置校验全部通过。

### 8.2 人工验收

- Windows 安装/卸载、broker ACL、TUN 启停、断网/换网、睡眠唤醒、回滚。
- Android 真机 VPN 流量、DNS/IPv6/WebRTC 泄漏、Wi-Fi/蜂窝切换、Doze、撤权、后台恢复。
- 发布包签名、哈希、16 KB 对齐、空节点池、自动更新失败回滚。

### 8.3 发布闸门

未完成 P0、存在未处置 Critical/High、CI 红、签名缺失、真机验收未完成时，不得发布正式版。

## 9. 文档同步

更新 `README.md`、`README.en.md`、`pc/README.md`、`phone/README.md`、`PUBLISH.md`、`THIRD_PARTY_NOTICES.md`、`pc/AI_HANDOVER.md`；新增 `SECURITY.md`、`PRIVACY.md`、`CONTRIBUTING.md`、`CHANGELOG.md`、迁移与发布手册。历史交接内容移入明确标注的归档，不再作为当前操作依据。

## 10. 分批交付

1. 共享策略与节点身份。
2. Windows 进程身份、控制面鉴权、fail-closed 与配置事务。
3. Windows broker、安装器、托盘与更新。
4. Android DNS、源签名、AI 路由、安全存储与生命周期。
5. Android UI、订阅、每应用代理与诊断。
6. CI/发布供应链与文档。
7. 全量回归、发布包验证、推送分支、CI 全绿后快进 `main`。

每批独立提交、独立测试；不在一批里混入无关重构。
