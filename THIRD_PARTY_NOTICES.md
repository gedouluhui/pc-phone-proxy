# 第三方组件与许可

本项目自己的代码（`phone/src`、`phone/build_apk.py`、`pc/_proxy/*.py` 等）使用 MIT 许可证，见 `LICENSE`。

手机 APK 与电脑端脚本依赖下列第三方开源项目。它们**不是**本项目的代码，各自遵循原许可证；本仓库不修改它们的源码。发布预编译 APK 时，这些组件以未修改的二进制形式一并分发。

## 手机端

| 组件 | 版本（构建时） | 许可证 | 来源 |
|---|---|---|---|
| Xray-core | v26.10.31 | Mozilla Public License 2.0 (MPL-2.0) | https://github.com/XTLS/Xray-core |
| AndroidLibXrayLite | v26.10.31（Lib v40） | GNU Lesser General Public License 3.0 (LGPL-3.0) | https://github.com/2dust/AndroidLibXrayLite |
| libXray（Go 绑定） | 随 AndroidLibXrayLite | MIT | https://github.com/XTLS/libXray |
| geoip.dat / geosite.dat | 构建时快照 | GPL-3.0（数据文件来自 v2ray-rules-dat） | https://github.com/Loyalsoldier/v2ray-rules-dat |

说明：

- `libv2ray.aar` 由 AndroidLibXrayLite 提供，包含 Xray-core 的 Go 静态库（`libgojni.so`）与 Java 绑定。APK 以未修改形式链接该库；如需替换/重新链接，可用本仓库的 `phone/build_apk.py` 与同版本 AAR 重建。
- `geoip.dat` / `geosite.dat` 是路由规则数据，构建时从 `phone/libs/xray/assets/` 打包进 APK。若你的构建目录没有这两个文件，请从上述数据源获取同格式文件。
- 本项目不包含也不分发 Xray-core / AndroidLibXrayLite 的源码；对应源码请从上述链接获取。

## 电脑端

| 组件 | 用途 | 许可证 | 来源 |
|---|---|---|---|
| sing-box | 代理内核（`pc/_proxy/bin/sing-box.exe`，需自行下载） | GPL-3.0-or-later | https://github.com/SagerNet/sing-box |
| Python | 运行脚本的解释器（不随仓库分发） | PSF License | https://www.python.org |
| requests | HTTP 客户端 | Apache-2.0 | https://github.com/psf/requests |
| websocket-client | Clash API WebSocket | Apache-2.0 | https://github.com/websocket-client/websocket-client |

说明：

- 本仓库**不包含** `sing-box.exe`。使用说明要求用户从官方 release 自行下载；若你分发包含该二进制的便携包，请同时遵守 GPL-3.0 的源码提供义务。
- 电脑端脚本调用的公开节点列表由各列表维护者提供，节点本身属于第三方，本项目不对其可用性、合法性或安全性作任何担保。

## 免责声明

本项目仅供学习、网络协议研究与个人使用。请遵守你所在地区的法律法规以及目标服务的服务条款。使用第三方节点产生的风险由使用者自行承担。
