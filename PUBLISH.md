# 发布到 GitHub（维护者步骤）

本仓库已公开：<https://github.com/gedouluhui/pc-phone-proxy>。当前版本线为 **v4.0.0**。
不要 force push，不要用 `commit --amend` 改历史；新修复创建新提交，CI 全绿后才能非 force 快进 `main`。

## 0. 发布前自检

在仓库根目录执行：

```bash
python tools/check_ci_supply_chain.py
python tools/verify_sources.py
python tools/sync_policy.py --check
python tools/run_ci_tests.py
python phone/tests/run_catalog_poc.py
python phone/check_release.py
python pc/check_release.py
```

`phone/check_release.py` 与 `pc/check_release.py` 必须确认 git 没有跟踪节点凭据、keystore、APK 或 Windows 二进制。
真实 Windows TUN/UAC/安装升级卸载、托盘 GUI 与 Android 真机 VPN/Keystore/网络切换/泄漏/续航/无障碍未验收前，
不得把离线 CI 写成生产验收通过。

## 1. Android 公版 APK

公开构建必须同时满足：

- `PROXY_RELEASE=1`：要求已有 keystore 和非空、非演示口令 `PROXY_KS_PASS`，绝不自动生成密钥。
- `--public`：所选节点输入必须恰为空数组，最终 APK 内唯一的 `assets/nodes.json=[]`。
- JDK 17、Android SDK build-tools 与 `android-36` platform。
- `phone/libs/libv2ray.aar` 为 v26.11.9，SHA-256
  `cdfef146218233a31a8b52c8b1016557730d3b63fc121d4c84cacea50e669155`。

```bash
PROXY_RELEASE=1 \
PROXY_KEYSTORE=/secure/path/phoneproxy.keystore \
PROXY_KS_ALIAS=phoneproxy \
PROXY_KS_PASS='<non-demo password from a secret channel>' \
PROXY_NODES_JSON=phone/assets/nodes.sample.json \
PROXY_APK_OUT=dist/手机代理-公版.apk \
python phone/build_apk.py --public
python phone/check_release.py dist/手机代理-公版.apk
```

`build_apk.py` 会完成 javac、d8、aapt2、签名、验签和 16 KiB 对齐检查，验证成功后原子替换产物。
本机 2026-11-28 的桌面 APK 沿用既有测试 keystore，**不是**上述正式签名流程。

## 2. Windows 安装包

准备以下被 `.gitignore` 排除的构建输入：

- `pc/runtime/python/`：内嵌 CPython 与 `pc/_proxy/requirements.txt` 的依赖。
- `pc/runtime/tray.exe`：由 `pc/app/tray.py` 构建的 PyInstaller 托盘，先运行 `tray.exe --version` 冒烟。
- `pc/_proxy/bin/sing-box.exe`：sing-box 1.14.4，ZIP SHA-256
  `99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`。
- `pc/_proxy/bin/wintun.dll`：0.14.1，当前观察到的 DLL SHA-256
  `d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931`，并验证 WireGuard LLC 签名。

用 Inno Setup 7.1.1 编译：

```bash
ISCC.exe pc/installer/PhoneProxy.iss
python pc/check_release.py pc/dist/PhoneProxy-Setup-4.0.0.exe
```

安装版将代码放在 `Program Files\PhoneProxy`，用户数据放在 `%LOCALAPPDATA%\PhoneProxy`。
TUN 由 broker 按需请求 UAC；便携版不得注册提权计划任务。

**本机生成的安装包没有 Authenticode 签名。正式对外发布前必须用生产代码签名证书签名托盘和安装包，
并让 `PROXY_RELEASE=1 python pc/check_release.py <installer>` 通过；不要把本地未签名包标成正式发行版。**

## 3. GitHub Actions

- `.github/workflows/ci.yml`：每次 push/PR 跑 Windows/Android 编译、回归、Proof、投毒语料和发布闸门。
- `.github/workflows/phone-apk.yml`：手动构建公版 APK，可上传到指定 Release。
- `.github/workflows/release.yml`：推送 `v*` tag 或手动触发时构建并发布公版 APK。

`phone-apk.yml` 需要：

- `secrets.PHONE_KS_B64`：keystore 的 base64。
- `secrets.PHONE_KS_PASS`：keystore/key 口令。

`release.yml` 需要：

- `secrets.PROXY_KEYSTORE_BASE64`
- `secrets.PROXY_KS_PASS`
- `vars.PROXY_KS_ALIAS`
- `vars.RELEASE_SIGNING_READY=1`

 secret 缺失时不要绕过守卫，也不要把演示口令 `android` 改成生产口令。

## 4. 更新清单与发布资产

Windows 更新只接受与 `pc/app/release-public.pem` 对应的私钥签名、SHA-256/大小匹配且版本递增的清单：

```bash
python tools/release_manifest.py --create <spec.json> \
  --private-key <offline-private-key.pem> \
  --manifest dist/release-manifest.json \
  --signature dist/release-manifest.sig
python tools/release_manifest.py --verify \
  --manifest dist/release-manifest.json \
  --signature dist/release-manifest.sig \
  --public-key pc/app/release-public.pem
```

发布 Release 时资产名使用 ASCII（如 `PhoneProxy-public.apk`、`PhoneProxy-Setup-4.0.0.exe`），
上传后重新下载并核对 SHA-256。SBOM/provenance 由 `tools/generate_sbom.py` 与
`tools/generate_provenance.py` 生成；不要把生成物里的本机绝对路径当作可复现入口。

## 5. 永远不要公开

`pinned.json`、`phone/assets/nodes.json`、`node_deep*.json`、订阅 URL/token、`*.keystore`、
私钥、真实诊断数据和含节点 APK。节点 URI 含 UUID/密码，keystore 与签名私钥等于更新权。
需要排除已误跟踪文件时用 `git rm --cached <path>` 保留本地副本，不要 `git add -f`。

## 6. 合规边界

代码加固不构成在中国大陆提供跨境网络服务的法律授权。商业发布前仍需专业法律、电信、App 备案、
隐私与数据保护评审，并准备隐私政策、支持渠道、漏洞披露和真实设备验收记录。
