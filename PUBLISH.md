# 发布到 GitHub（维护者步骤）

本地已经是一个提交好的 git 仓库（分支 `main`）。因为这台机器上既没有 GitHub 登录凭据、
也没有 `gh` 命令行，最后一步「建仓库 + push + 上传 Release」需要你在网页上完成，约 3 分钟。

## 0. 发布前自检

在仓库目录执行：

```bash
git log --oneline -1
git ls-files | grep -E "pinned\.json|nodes\.json|node_deep|\.keystore|dist/.*\.apk"
```

第二条**应该没有任何输出**。若列出了文件，先不要 push：先把清单里的凭据移出仓库或加进 `.gitignore`。

## 1. 建一个空仓库

打开 <https://github.com/new>：

- Repository name：`pc-phone-proxy`（想换名字可以换，下面命令同步改）
- 可见性：**Public**
- **不要**勾选 "Add a README file" / ".gitignore" / "license"（本地已有，勾了会冲突）

点 **Create repository**。

## 2. 首次 push

GitHub 的创建成功页会显示仓库地址。在仓库目录执行：

```bash
git remote add origin https://github.com/<你的用户名>/pc-phone-proxy.git
git push -u origin main
```

第一次 push 会弹窗要求登录 GitHub（Git Credential Manager / 浏览器授权）。
登录一次之后，以后 push 不用再输密码。

> 如果弹窗授权失败，可以在 GitHub「Settings → Developer settings → Personal access tokens」
> 建一个只勾 `repo` 权限的 token，push 时用户名填 GitHub 用户名、密码填 token。
> token 等同于密码，不要粘贴到聊天、文档或截图里。

## 3. 发布公版 APK（Release）

1. 打开仓库页 → 右侧 **Releases** → **Draft a new release**
2. **Choose a tag**：输入 `v2.6` → 点 "Create new tag: v2.6 on publish"
3. Release title：`v2.6 — 真内核预检、假死流放行、单实例 TUN`
4. 描述可以直接复制：

   ```text
   v2.6。

   手机端：PhoneProxy-public.apk（Android 7.0+，不内置节点，安装后导入自己的分享链接/订阅）
   - 导入与启动前用真 Xray 内核做零网络配置预检，坏节点自动隔离
   - AI 闸门缓存 1 天；observatory 探针 16KB / 10 分钟

   电脑端：见仓库 pc/ 目录，Windows 10/11 x64（V3.2）
   - TUN 单实例，原 2098 GAI 出口并入主配置
   - 低速假死流判定放行；PC 解析器投毒用例

   SHA256（PhoneProxy-public.apk）：
   0890349b80f591932847054b1f45c0b61bb8eb3ec8e0225a2a229192ac8651ff
   ```

5. 把 `dist/手机代理-公版.apk` 拖进 **Attach binaries** 区域（约 54 MB，上传需要一会儿）
6. 点 **Publish release**

> GitHub 会把 Release 资产名里的中文剥掉（实测 `手机代理-公版.apk` 会变成 `-.apk`），所以资产名统一用 ASCII 的 `PhoneProxy-public.apk`；本地构建产物仍叫 `手机代理-公版.apk`，两者字节相同。

> **发版前对一遍版本**：`phone/AndroidManifest.xml` 的 `versionName` 是源码真相，
> `dist/SHA256SUMS.txt` 是**已发布资产**的校验值，两者必须同时更新，否则源码说 2.6、
> 用户下到的还是 2.5 且校验值对不上。
>
> 电脑端（2026-11-23）：仓库内 PC 脚本为 **V3.2**（真关闭 / 静态代理兜底 /
> 下载保护 / 低速假死流放行 / TUN 单实例），以源码形式发布，不随 APK 资产打包。
>
> 当前状态（2026-11-23）：源码 **v2.6**，公版 APK 已构建完成，**待上传为 v2.6 Release**。
> 资产 `PhoneProxy-public.apk` 56,964,102 B，
> SHA256 `0890349b80f591932847054b1f45c0b61bb8eb3ec8e0225a2a229192ac8651ff`，
> 与 `dist/手机代理-公版.apk` 字节一致。上传完成后把本行改成「已发布 **v2.6**」。
>
> **公开版必须 `python build_apk.py --public`**。不带参数时脚本会把本地
> `assets/nodes.json`（真实节点凭据）打进 APK；2026-11-18 第一次发的 v2.5 资产就是这样
> 把 24 个节点带上去的，十分钟后才发现并替换。现在 `--public` 会强制空表并在打包后
> 读回 APK 断言节点数为 0；发版前运行
> `python phone/check_release.py dist/手机代理-公版.apk`，必须打印 `assets/nodes.json = []`。

## 4. 发布后验证

- 仓库首页的 README 能正常显示，图片 `docs/phone-connected.png` 能打开。
- Releases 页面能看到 `PhoneProxy-public.apk`，下载后校验：

  ```bash
  # Windows PowerShell
  Get-FileHash .\PhoneProxy-public.apk -Algorithm SHA256
  ```

  结果应为 `0890349B80F591932847054B1F45C0B61BB8EB3EC8E0225A2A229192AC8651FF`。
- 用手机浏览器打开 Release 页面，确认能下载并安装。

## 5. 可选：让提交作者显示成你自己

本地这次提交用的是占位身份。如果你想把它改成自己的 GitHub 身份：

```bash
git config user.name "你的名字"
git config user.email "你的邮箱"
git commit --amend --reset-author --no-edit
git push -f origin main   # 仅在还没别人克隆时使用
```

## 6. 不要公开的东西（再强调一次）

以下文件已被 `.gitignore` 排除，**永远不要**用 `git add -f` 强行提交：
`pinned.json`、`phone/assets/nodes.json`、`node_deep*.json`、`*.keystore`、`dist/*.apk`。
节点 URI 里含 UUID/密码，keystore 是签名私钥；公开等于把节点和 APP 更新权一起送人。
