# 发布到 GitHub（维护者步骤）

本地已经是一个提交好的 git 仓库（分支 `main`）。因为这台机器上既没有 GitHub 登录凭据、
也没有 `gh` 命令行，最后一步「建仓库 + push + 上传 Release」需要你在网页上完成，约 3 分钟。

## 0. 发布前自检

在仓库目录执行：

```bash
git log --oneline -1
git ls-files | grep -E "pinned\.json|nodes\.json|node_deep|\.keystore|dist/.*\.apk"
```

第二条**应该没有任何输出**。若列出了文件，先不要 push，告诉我文件清单。

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
2. **Choose a tag**：输入 `v1.0.0` → 点 "Create new tag: v1.0.0 on publish"
3. Release title：`v1.0.0 — 手机 + 电脑 双端代理`
4. 描述可以直接复制：

   ```text
   首个公开版本。

   手机端：手机代理-公版.apk（Android 7.0+，不内置节点，安装后导入自己的分享链接/订阅）
   电脑端：见仓库 pc/ 目录，Windows 10/11 x64

   SHA256（手机代理-公版.apk）：
   fb92da28181edd5c07ff3cf6961fee846195bed8f60e27a051cf0e4cbd29c06b
   ```

5. 把 `dist/手机代理-公版.apk` 拖进 **Attach binaries** 区域（约 54 MB，上传需要一会儿）
6. 点 **Publish release**

## 4. 发布后验证

- 仓库首页的 README 能正常显示，图片 `docs/phone-connected.png` 能打开。
- Releases 页面能看到 `手机代理-公版.apk`，下载后校验：

  ```bash
  # Windows PowerShell
  Get-FileHash .\手机代理-公版.apk -Algorithm SHA256
  ```

  结果应为 `FB92DA28181EDD5C07FF3CF6961FEE846195BED8F60E27A051CF0E4CBD29C06B`。
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
