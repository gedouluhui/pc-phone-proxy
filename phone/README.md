# 手机端：构建说明

一个自研的 Android 代理 App（包名 `com.luhui.phoneproxy`），Java 外壳 + Xray 内核。
不需要 Gradle，`build_apk.py` 直接调用 JDK / Android SDK 命令行工具完成构建。

## 环境

| 依赖 | 说明 |
|---|---|
| JDK 17 | 设置 `JAVA_HOME`，或改脚本里的 `find_jdk()` |
| Android SDK | 需要 build-tools（含 d8/aapt2/zipalign/apksigner）和一个 `android-35` platform；设置 `ANDROID_HOME` / `ANDROID_SDK_ROOT` |
| AndroidLibXrayLite | 下载 `libv2ray.aar` 放到 `phone/libs/libv2ray.aar` |
| Python 3.8+ | 仅用于运行构建脚本 |

`libv2ray.aar` 下载地址：<https://github.com/2dust/AndroidLibXrayLite/releases>
（选与 Xray-core v26.x 对应的版本；本项目验证过 v26.10.31 / Lib v40。）
脚本会自动解压 AAR 到 `phone/libs/xray/`，里面已包含四个 ABI 的 `libgojni.so` 以及 `geoip.dat` / `geosite.dat`。

## 构建

```bash
cd phone
python build_apk.py
```

首次构建会自动生成签名用的 `phoneproxy.keystore`（口令 `android`，仅用于本地安装，不是任何账号凭据）。
产物默认是 `phone/手机代理.apk`。

> 自己构建的 APK 用的是上面这个新生成的密钥，和 Release 里公版 APK 的签名不同。
> 如果手机上已经装了 Release 版，覆盖安装会报“应用未安装 / 签名不一致”，请先卸载旧版再装。

### 内置自己的节点

App 支持两种节点来源：安装包内置（`assets/nodes.json`）和用户导入。
公共版不内置任何节点；要做一个只给自己用的版本：

```bash
# 方式 A：从电脑端 pinned.json（分享链接 -> outbound）
python gen_nodes.py /path/to/pinned.json

# 方式 B：从电脑端深测结果挑 24 个（推荐，保留原始分享链接）
PROXY_DIR=/path/to/代理便携版/_proxy python gen_pool.py

python build_apk.py
```

`assets/nodes.json` 已被 `.gitignore` 忽略，**不要把它提交到公开仓库**。

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
| `src/.../ConfigBuilder.java` | 生成 Xray 配置：出站、observatory、两个 balancer、分流规则、DNS |
| `AndroidManifest.xml` | minSdk 24 / targetSdk 33，VPN Service 声明 |
| `build_apk.py` | javac → d8 → aapt2 → zip → zipalign → apksigner |
| `gen_nodes.py` / `gen_pool.py` | 把电脑端节点数据转换/挑选成 `assets/nodes.json` |

## 实现要点

- **分流**：`geosite:cn`、`geoip:cn`、`geoip:private` 走 `direct`；其余走 `proxy`。
- **自动选线**：Xray `observatory` 每 30 秒探测所有节点；`balancer` 按最低延迟选路，节点失败自动切换。
- **ChatGPT**：通过 `cg=true` 的节点组成 `cg-balancer`，只给 OpenAI/Anthropic 域名使用。
- **防回环**：VPN 建立时 `addDisallowedApplication(自身包名)`，App 自己的流量不走 TUN。
- **DNS**：国内 `223.5.5.5` 直连解析；国外域名走 Cloudflare DoH（经代理）。
- **导入**：分享链接逐条解析，失败的单条跳过并写日志；订阅地址下载后按行解析。
- **空池保护**：节点池为空时不启动 VPN，弹窗引导导入。

## 许可

App 使用 MIT；Xray-core（MPL-2.0）、AndroidLibXrayLite（LGPL-3.0）等第三方组件见仓库根目录 `THIRD_PARTY_NOTICES.md`。
