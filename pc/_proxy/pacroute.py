# -*- coding: utf-8 -*-
"""Split-routing PAC: one system setting that sends each site through the proxy
that actually works for it.

Why: measured on 2026-11-09 (site_probe2.json) --
  * 迷雾通 Geph (exit LT)  : chatgpt.com 200 (real app page), claude.ai reachable,
                             but kaggle.com / ipinfo.io 403 (Google armor) and
                             youtube/hf very slow.
  * sing-box 免费节点 (HK) : kaggle/github/hf/google/youtube/reddit 200 and fast,
                             but chatgpt.com 403 unsupported_country; claude.ai
                             302 app-unavailable-in-region.
  * 公开 HTTP 代理         : 全部 CONNECT 被重置（含刚被选为"最快"的那个），
                             不可用于任何浏览。

So: a PAC file served on 127.0.0.1 that routes per domain. Kaggle is DIRECT
(it is not blocked from here and every API call we make is direct).

CLI:
  python pacroute.py apply             # write PAC, start server, set WinINET
  python pacroute.py status
  python pacroute.py off
  python pacroute.py serve             # foreground server (used with pythonw)
"""
import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
PAC_PATH = os.path.join(HERE, "proxy.pac")
PAC_URL_PATH = os.path.join(HERE, "pac_url.txt")
PID_PATH = os.path.join(HERE, "pac_server.pid")
LOG_DIR = os.path.join(HERE, "logs")
PORT = 8891
K = winreg.HKEY_CURRENT_USER
IS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

DEFAULT_GENERAL = "127.0.0.1:9910"   # Geph HTTP
DEFAULT_FAST = "127.0.0.1:2086"      # sing-box HTTP inbound
DEFAULT_HK = "127.0.0.1:2086"        # 香港免费节点（reddit 只在这条线上通）

DOMESTIC = [
    # 国内 AI / 编程工具：开代理后必须直连。走国外免费节点会被 WAF 拒或极慢，
    # 用户实测 Kimi Code 在兜底走代理后直接"没网"。
    "kimi.com", "moonshot.cn", "moonshotai.cn",
    "deepseek.com", "deepseek.ai",
    "doubao.com", "volces.com", "volcengine.com",
    "tongyi.aliyun.com", "dashscope.aliyuncs.com",
    "chatglm.cn", "zhipuai.cn", "bigmodel.cn",
    "baichuan-ai.com", "minimax.chat", "hailuoai.com",
    "metaso.cn", "tiangong.cn", "yiyan.baidu.com",
    "codebuddy.cn", "workbuddy.cn", "tencent.com", "qq.com",
    "cn", "baidu.com", "bdstatic.com", "qq.com", "gtimg.com", "taobao.com",
    "tmall.com", "alicdn.com", "alipay.com", "aliyun.com", "jd.com",
    "bilibili.com", "hdslb.com", "douyin.com", "byteimg.com", "bytedance.com",
    "zhihu.com", "zhimg.com", "weibo.com", "sina.com.cn", "163.com",
    "126.net", "csdn.net", "gitee.com", "mi.com", "xiaomi.com", "huawei.com",
    "xiaohongshu.com", "xhscdn.com", "kuaishou.com", "meituan.com", "163yun.com",
    "tencent.com", "wechat.com", "weixin.qq.com",
    # 2026-11-10 扩充：更多国内站点走直连，避免绕路/验证码
    "pinduoduo.com", "yangkeduo.com", "dianping.com", "ctrip.com", "qunar.com",
    "12306.cn", "amap.com", "autonavi.com", "iqiyi.com", "youku.com",
    "mgtv.com", "douban.com", "xueqiu.com", "eastmoney.com", "sina.com",
    "sohu.com", "ifeng.com", "aliyuncs.com", "myqcloud.com", "qcloud.com",
    "tencentcloudapi.com", "huaweicloud.com", "volces.com", "doubao.com",
    "deepseek.com", "moonshot.cn", "kimi.com", "moonshot.ai", "smzdm.com",
    # 2026-11-11 WorkBuddy hotfix: 米哈游全家桶必须直连（海外节点到不了国服登录/网关，
    # 原神登录会卡死在 000 超时）。覆盖原神/星铁/绝区零/米游社/HoYoLAB。
    "mihoyo.com", "yuanshen.com", "hoyoverse.com", "hoyolab.com",
    "miyoushe.com", "bh3.com", "starrail.com", "zzz.mihoyo.com", "hkrpg.com",
    # 2026-11-11 WorkBuddy hotfix2: 字节系 CDN 必须直连（只有 douyin.com 主域直连不够，
    # 视频/图片/静态资源走海外节点全 000 超时 → 抖音网页版主站开但页面卡死）。
    "douyinvod.com", "douyinpic.com", "douyinstatic.com", "douyincdn.com",
    "douyixiaoshipin.com", "isnssdk.com", "snssdk.com", "pstatp.com",
    "bytecdntp.com", "byteimg.com", "bytednsdoc.com", "bytegoofy.com",
    "volccdn.com", "amemv.com", "zjcdn.com", "ixigua.com", "feishu.cn",
    "volcengine.com", "toutiao.com", "melon.com", "fanqienovel.com",
    "58.com", "anjuke.com", "zhaopin.com", "51job.com", "cnblogs.com",
    "oschina.net", "jianguoyun.com", "nuomi.com", "kuaidi100.com",
    # 2026-11-12 WorkBuddy hotfix3: 魔搭/ModelScope 必须直连（走海外节点会被阿里风控判 RGV587）。
    "modelscope.cn", "modelscope.com", "aliyun.com", "alicdn.com",
    # 2026-11-12 WorkBuddy hotfix4: 常用国内 CDN / 开放平台（无 .cn，极易被漏）。
    "alipayobjects.com", "qpic.cn", "gtimg.cn", "weixin.com", "wechat.com",
    "wechatpay.com", "tenpay.com", "qqmail.com", "foxmail.com", "dingtalk.com",
    "feishu.net", "larksuite.com", "bytedns.net", "volcimage.com", "pstatp.com",
]
# 走 HK 快速节点（免费节点 + 迷雾通兜底）
FAST = [
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "gvt1.com", "ggpht.com", "youtube.com", "youtu.be", "ytimg.com",
    "googlevideo.com", "withgoogle.com",
    "github.com", "githubusercontent.com", "githubassets.com", "github.io",
    "githubcopilot.com", "ghcr.io",
    "huggingface.co", "hf.co", "hfusercontent.com", "cdn-lfs.huggingface.co",
    "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
    "x.com", "twitter.com", "twimg.com", "t.co",
    "wikipedia.org", "wikimedia.org", "wiktionary.org",
    "npmjs.com", "pypi.org", "python.org", "nodejs.org", "rust-lang.org",
    "stackoverflow.com", "sstatic.net", "arxiv.org", "openreview.net",
    "discord.com", "discordapp.com", "discord.gg", "telegram.org", "t.me",
    # OpenAI 的静态资源/图片 CDN 不做地区封锁：页面 90% 的字节在这里，
    # 走快出口能把 ChatGPT 打开速度拉起来（Geph 只需扛 HTML/API）。
    "oaistatic.com", "oaiusercontent.com", "blob.core.windows.net",
    # 2026-11-10 扩充：开发者/常用外网服务
    "npmjs.org", "yarnpkg.com", "nodejs.org", "pythonhosted.org",
    "files.pythonhosted.org", "crates.io", "deps.rs", "golang.org",
    "go.dev", "proxy.golang.org", "sum.golang.org", "rustup.rs",
    "docker.com", "docker.io", "quay.io", "jetbrains.com", "code.visualstudio.com",
    "vscode-cdn.net",
    "slack.com", "slack-edge.com", "notion.so", "notion.site", "figma.com",
    "medium.com", "substack.com", "quora.com", "producthunt.com",
    "instagram.com", "facebook.com", "fbcdn.net", "messenger.com",
    "twitch.tv", "spotify.com", "scdn.co", "soundcloud.com",
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "reuters.com",
    "translate.googleapis.com",
    # 2026-11-19 驱动/系统下载：NVIDIA、打印机厂商的下载 CDN 在国内直连常年
    # 只有几十 KB/s 甚至 0 字节。这些厂商的安装器大多不读 PAC，真正的兜底是
    # 启动时同时写入的静态代理 127.0.0.1:2090；列在这里让浏览器也走快出口。
    "nvidia.com", "nvidia.cn", "geforce.com", "geforce.cn",
    "amd.com", "intel.com", "realtek.com",
    "hp.com", "hp.com.cn", "hpsmart.com",
    "canon.com", "canon.com.cn", "epson.com", "epson.com.cn",
    "brother.com", "brother.com.cn", "dell.com", "dell.com.cn",
    "download.microsoft.com", "software-download.microsoft.com",
    "catalog.update.microsoft.com", "windowsupdate.com",
]
# 只有 Geph（LT 出口）能过
GENERAL = [
    "chatgpt.com", "openai.com",
    "chatgpt.livekit.cloud", "sora.chatgpt.com", "platform.openai.com",
    "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
    "gemini.google.com",   # 注意：gemini 走 HK 更好，见下
]
# gemini 实测 Geph 403 / HK 200，所以从 GENERAL 里剔除
GENERAL = [d for d in GENERAL if d != "gemini.google.com"]
FAST.append("gemini.google.com")
# Kaggle 直连（未被墙，且两个代理都拒）
# 2026-11-11 WorkBuddy privacy: 敏感域（银行/支付/政务/社保/税务/内网 OA）永不经过免费节点。
# 这些站点直连即可访问，走第三方免费节点等于把账号密码的 TLS 目标暴露给节点运营者。
SENSITIVE = [
    "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankofchina.com",
    "cmbchina.com", "bocom.cn", "psbc.com", "cmbc.com.cn", "spdb.com.cn",
    "ecitic.com", "cib.com.cn", "hxb.com.cn", "cgbchina.com.cn", "cebbank.com",
    "unionpay.com", "95516.com", "paypal.com", "alipay.com", "tenpay.com",
    "gov.cn", "chinatax.gov.cn", "12333.gov.cn", "12366.gov.cn", "pbc.gov.cn",
    "csrc.gov.cn", "nfra.gov.cn", "edu.cn", "si.12333.gov.cn",
    # 2026-11 补：银行/支付/账号体系，永不经过第三方节点
    "pingan.com", "bankcomm.com", "citicbank.com", "spdb.com", "jdpay.com",
    "baifubao.com", "apple.com", "icloud.com", "icloud.com.cn",
    "microsoftonline.com", "live.com",
]

DIRECT = ["kaggle.com", "kaggleusercontent.com", "ipinfo.io"]
# ---- Steam: 商店/社区/登录走美国出口（用户要外区商店），下载 CDN 走直连 ----
STEAM = [
    "steampowered.com", "steamcommunity.com", "steamstatic.com",
    "steam-chat.com", "steamgames.com", "steamusercontent.com",
    "steamserver.com", "steamdeck.com", "steam.tv", "valvesoftware.com",
    "s.team", "steamcommunity-a.akamaihd.net", "steamstore-a.akamaihd.net",
    # Wallpaper Engine（CEF）创意工坊：预览图/CDN 也要走外网，否则页面空白
    "steamuserimages-a.akamaihd.net", "steamusercontent-a.akamaihd.net",
    "wallpaperengine.io",
    # 2026-11-15 实测：ChatGPT 在 2096（美国）200、在 2086 是 403；
    # Claude 反过来（2086 200、2096 403）=> 两家必须分开走不同出口。
    "chatgpt.com", "openai.com", "chatgpt.livekit.cloud", "sora.chatgpt.com",
    "platform.openai.com", "oaistatic.com", "oaiusercontent.com",
    "auth.openai.com", "auth0.openai.com",
]
# 必须走「支持 Gemini 的地区」的服务主体。香港 IP 不在支持列表，一旦落到
# 2086 会被强制跳到 "Available regions" 文档页，连对话都开不了。
# 优先级最高（仅次于内网/国内直连），不受任何动态/静态组覆盖。
GOOGLE_APP = ["aistudio.google.com", "makersuite.google.com", "gemini.google.com",
              "notebooklm.google.com", "labs.google",
              # AI Studio 的 API 调用也走这些域，同样受地区限制；
              # 它们原来被 DYN_GOOGLE 带去香港，会导致页面能开、请求全挂。
              "generativelanguage.googleapis.com",
              "alkalimakersuite-pa.clients6.google.com",
              "aida.googleapis.com", "cloudaicompanion.googleapis.com",
              # Google Antigravity（反重力 IDE）。它的登录资格校验走
              # cloudcode-pa，实测不带凭据返回 401 说明链路通；资格由 Google
              # 按地区判定，所以这些域名必须和 AI Studio 走同一个合格出口，
              # 否则落到被 Google 拒的节点上就会得到 ineligible。
              "antigravity.google", "cloudcode-pa.googleapis.com",
              "daily-cloudcode-pa.googleapis.com",
              "jetski-webchannel.googleapis.com"]

STEAM_DIRECT = ["steamcontent.com", "steamcdn-a.akamaihd.net"]
DIRECT += STEAM_DIRECT
DEFAULT_STEAM = "127.0.0.1:2096"      # 美国出口（sing-box，start_proxy 负责拉起）
DEFAULT_GAI = "127.0.0.1:2098"        # Google AI 专用出口（过了地区闸门的节点）
# 实测只有香港那条线能过（fast/general/geph 全是 403 "blocked by network security"）
HK = ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
      "redditinc.com", "reddithelp.com",
      # Claude：只有香港这条线能过 Cloudflare（2096 美国出口返回 403）
      "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
      # Gemini / AI Studio 不放香港：香港 IP 不在 Gemini 支持地区，会被跳转到
      # "Available regions" 文档页。它们跟着 FAST 的 google.com 走 2103（西班牙）。
      # Google 的静态资源/API 香港最快（0.43~0.51s），但**只能放静态域**：
      # 香港 IP 不在 AI Studio / Gemini 的支持地区列表里，google.com 一旦进这个
      # 列表，aistudio.google.com 会被强制重定向到 "Available regions" 文档页，
      # 连对话框都打不开。google.com / gemini.google.com 必须走 FAST(2103 西班牙)。
      # youtube.com / googlevideo.com / ytimg.com 也不放这里——视频要带宽。
      "gstatic.com", "googleapis.com", "googleusercontent.com",
      "gvt1.com", "ggpht.com", "withgoogle.com"]


def _identifier(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
        raise ValueError("PAC rule identifier must be ASCII")
    # Include legacy/future reserved words for the older JavaScript PAC interpreters.
    reserved = set(("break case catch continue debugger default delete do else finally for "
                    "function if in instanceof new return switch this throw try typeof var void "
                    "while with false null true class const enum export extends import super "
                    "implements interface let package private protected public static yield await "
                    "abstract boolean byte char double final float goto int long native short "
                    "synchronized throws transient volatile eval arguments").split())
    if name in reserved:
        raise ValueError("reserved PAC rule identifier")
    return name


def _js_list(name, domains):
    _identifier(name)
    if not isinstance(domains, (list, tuple)):
        raise ValueError("PAC domains must be a list")
    normalized = []
    for domain in domains:
        if not isinstance(domain, str) or not domain.isascii():
            raise ValueError("PAC domains require ASCII (use IDNA A-labels, not Unicode)")
        domain = domain.lower().removesuffix(".")
        if (not domain or len(domain) > 253 or
                any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in domain.split("."))):
            raise ValueError("invalid PAC domain; wildcards and empty labels are not supported")
        if domain not in normalized:
            normalized.append(domain)
    return "var %s = %s;" % (name, json.dumps(normalized, ensure_ascii=True))


def _endpoint(ep):
    if not isinstance(ep, str) or not re.fullmatch(r"(?:127\.0\.0\.1|\[::1\]):[0-9]{1,5}", ep):
        raise ValueError("PAC endpoint must be loopback host:port")
    host, port = ep.rsplit(":", 1)
    if not 1 <= int(port) <= 65535:
        raise ValueError("PAC endpoint port out of range")
    return "%s:%d" % (host, int(port))


def _chain(eps, direct=True):
    """Validate and deduplicate local exits; an empty protected chain is an error."""
    seen = []
    for ep in eps:
        if ep is None or ep == "":
            continue
        ep = _endpoint(ep)
        if ep not in seen:
            seen.append(ep)
    if not seen and not direct:
        raise ValueError("no local exit for protected PAC route")
    return "; ".join(["PROXY " + ep for ep in seen] + (["DIRECT"] if direct else []))


def render_pac(general=DEFAULT_GENERAL, fast=DEFAULT_FAST, stamp=None, hk=None, steam=None,
               dyn=None, gai=None):
    # Base exits are required, as in apply_pac's preflight. Rendering never probes them.
    general, fast = _endpoint(general), _endpoint(fast)
    hk = None if hk is None or hk == "" else _endpoint(hk)
    steam = None if steam is None or steam == "" else _endpoint(steam)
    gai = None if gai is None or gai == "" else _endpoint(gai)
    stamp = stamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not isinstance(stamp, str):
        raise ValueError("PAC stamp must be text")

    def rule(name, eps, direct):
        return "  if (inList(host, %s)) return %s;\n" % (
            name, json.dumps(_chain(eps, direct), ensure_ascii=True))

    # Preserve Google > Steam > HK > dynamic > FAST outlet priority in both paths.
    # Google AI Studio is region-gated by exit IP: the quickest node can be one
    # Google refuses (notebooklm answers location=unsupported).  A dedicated
    # exit that passed the region probe goes first when it is alive.
    google_chain = ([gai] if gai else []) + \
        ["127.0.0.1:2103", "127.0.0.1:2101", "127.0.0.1:2096"]
    routes = [("GOOGLE_APP", google_chain)]
    if steam:
        routes.append(("STEAM", [steam, fast, general]))
    if hk:
        routes.append(("HK", [hk, fast, general]))
    dyn_vars = ""
    if dyn is not None and not isinstance(dyn, dict):
        raise ValueError("PAC dynamic routes must be a mapping")
    for name, group in (dyn or {}).items():
        _identifier(name)
        if group is None:
            continue
        if not isinstance(group, dict):
            raise ValueError("PAC dynamic group must be a mapping")
        proxy = group.get("proxy")
        domains = group.get("domains", [])
        # Preserve case: uppercasing used to alias distinct route groups.
        var = "DYN_" + name
        declaration = _js_list(var, domains)
        if proxy is not None and proxy != "":
            proxy = _endpoint(proxy)
        if proxy is None or proxy == "" or not domains:
            continue
        dyn_vars += declaration + "\n"
        routes.append((var, [proxy, fast, general]))
    routes.append(("FAST", [fast, general]))
    protected_rules = "".join(rule(name, eps, False) for name, eps in routes)
    normal_rules = "".join(rule(name, eps, True) for name, eps in routes)
    return r"""// split-routing PAC; metadata is encoded data, never a comment interpolation.
var GENERATED_AT = %(stamp)s;
%(dom)s
%(sens_d)s
%(fast_d)s
%(gen_d)s
%(gapp_d)s
%(hk_d)s
%(steam_d)s
%(dyn_d)s
%(direct_d)s

function dom(h, d) { return h === d || dnsDomainIs(h, "." + d); }

function inList(h, list) {
  for (var i = 0; i < list.length; i++) { if (dom(h, list[i])) return true; }
  return false;
}

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host.charAt(host.length - 1) === ".") host = host.slice(0, -1);
  // GENERAL is the protected set; SENSITIVE below is the domestic direct-only set.
  // Protection outranks even direct/private list intersections, without losing exit choice.
  var protectedHost = inList(host, GENERAL);
  if (protectedHost) {
%(protected_rules)s  }
  if (inList(host, GENERAL)) return %(general_chain)s;
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" ||
      host === "[::1]" || isPlainHostName(host) || shExpMatch(host, "127.*") ||
      shExpMatch(host, "192.168.*") || shExpMatch(host, "10.*") ||
      shExpMatch(host, "172.1[6-9].*") || shExpMatch(host, "172.2[0-9].*") ||
      shExpMatch(host, "172.3[0-1].*") || shExpMatch(host, "169.254.*") ||
      shExpMatch(host, "100.6[4-9].*") || shExpMatch(host, "100.[7-9][0-9].*") ||
      shExpMatch(host, "100.1[0-1][0-9].*") || shExpMatch(host, "100.12[0-7].*")) {
    return "DIRECT";
  }
  // IPv6 私网/链路本地（PAC 里 host 带方括号）
  if (host.charAt(0) === "[" &&
      (host.indexOf("[fc") === 0 || host.indexOf("[fd") === 0 ||
       host.indexOf("[fe80:") === 0 || host.indexOf("[fe90") === 0 ||
       host.indexOf("[fea") === 0 || host.indexOf("[feb") === 0)) {
    return "DIRECT";
  }
  // 公司/家庭内网后缀。用纯字符串后缀判断而不是 dnsDomainIs/shExpMatch：
  // WinINet 的 PAC 解释器对 .local/.corp 这类单标签后缀匹配不可靠（实测漏判）。
  if (host.slice(-6) === ".local" || host.slice(-4) === ".lan" ||
      host.slice(-9) === ".internal" || host.slice(-5) === ".corp" ||
      host.slice(-10) === ".home.arpa") {
    return "DIRECT";
  }
  if (inList(host, DOMESTIC)) return "DIRECT";
  if (inList(host, SENSITIVE)) return "DIRECT";
  if (inList(host, DIRECT))   return "DIRECT";
  // Google retains its fixed support-region exits, ahead of Steam/HK/dynamic routes.
%(normal_rules)s  // Unlisted domains retain the product's proxy-first, direct-last policy.
  return %(default_chain)s;
}
""" % {
        "stamp": json.dumps(stamp, ensure_ascii=True),
        "protected_rules": protected_rules,
        "normal_rules": normal_rules,
        "general_chain": json.dumps(_chain([general, fast], False)),
        "default_chain": json.dumps(_chain([fast, general])),
        "dom": _js_list("DOMESTIC", DOMESTIC),
        "sens_d": _js_list("SENSITIVE", SENSITIVE),
        "fast_d": _js_list("FAST", FAST),
        "gen_d": _js_list("GENERAL", GENERAL),
        "gapp_d": _js_list("GOOGLE_APP", GOOGLE_APP),
        "hk_d": _js_list("HK", HK if hk else []),
        "steam_d": _js_list("STEAM", STEAM if steam else []),
        "dyn_d": dyn_vars,
        "direct_d": _js_list("DIRECT", DIRECT),
    }


def write_pac(general=DEFAULT_GENERAL, fast=DEFAULT_FAST, hk=None, steam=None, dyn=None,
              gai=None):
    text = render_pac(general, fast, hk=hk, steam=steam, dyn=dyn, gai=gai)
    with io.open(PAC_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return PAC_PATH


# ------------------------------------------------------------------ server
def _serve_forever(port=None):
    import http.server
    bind = int(port or PORT)

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path.split("?")[0] not in ("/proxy.pac", "/"):
                self.send_error(404)
                return
            try:
                data = io.open(PAC_PATH, "rb").read()
            except OSError:
                self.send_error(500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    http.server.ThreadingHTTPServer.allow_reuse_address = True
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", bind), H)
    # PAC 服务是这套栈里唯一「谁都不依赖」的长驻进程（DETACHED|NEW_GROUP、
    # 只读一个文件），所以让它当看门狗的守夜人。2026-11-18：看门狗被外部
    # TerminateProcess 之后没人知道，状态文件停在最后一刻，出口坏了也不会自愈。
    try:
        import threading
        threading.Thread(target=_guard_loop, name="wd-guard", daemon=True).start()
    except Exception:
        pass
    srv.serve_forever()


# ------------------------------------------------------- 看门狗保活（守夜人的守夜人）
WD_PID = os.path.join(HERE, "watchdog.pid")
WD_STOP = os.path.join(HERE, "STOP_WATCHDOG")
WD_GUARD = os.path.join(HERE, "watchdog_guard.json")


def _wd_alive():
    try:
        pid = int(io.open(WD_PID, encoding="utf-8").read().strip())
    except Exception:
        return False
    if pid <= 0:
        return False
    try:
        import proxyctl as P
        # PID 会被复用，必须确认是 python 才算活着
        return P.pid_image(pid).lower().startswith("python")
    except Exception:
        return False


def _spawn_watchdog():
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pyw if os.path.isfile(pyw) else sys.executable
    os.makedirs(LOG_DIR, exist_ok=True)
    with io.open(os.path.join(LOG_DIR, "watchdog.out"), "ab") as logf:
        p = subprocess.Popen([exe, os.path.join(HERE, "watchdog.py")], cwd=HERE,
                             stdout=logf, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             creationflags=0x00000008 | 0x00000200)
    return p.pid


def guard_watchdog():
    """看门狗没在跑就把它拉起来；连续秒退则退避 15 分钟再试。"""
    now = time.time()
    try:
        g = json.load(io.open(WD_GUARD, encoding="utf-8")) or {}
    except Exception:
        g = {}
    if now < float(g.get("retry_at") or 0):
        return False
    died_fast = (g.get("spawn_at") and now - float(g["spawn_at"]) < 180)
    try:
        pid = _spawn_watchdog()
    except Exception:
        return False
    g["spawn_at"] = now
    g["pid"] = pid
    g["retry_at"] = (now + 900) if died_fast else 0
    try:
        with io.open(WD_GUARD, "w", encoding="utf-8", newline="\n") as f:
            json.dump(g, f)
    except OSError:
        pass
    return True


def _guard_loop():
    while True:
        time.sleep(60)
        try:
            # ENABLED 不在 = 用户已关闭代理：守夜人也不许再拉起看门狗。
            if not os.path.isfile(os.path.join(HERE, "ENABLED")):
                continue
            # STOP_WATCHDOG 存在 = 用户正在关代理，别跟他抢
            if os.path.isfile(WD_STOP) or _wd_alive():
                continue
            guard_watchdog()
        except Exception:
            pass


def _port_open(port=PORT):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def ep_port(ep):
    try:
        return int(str(ep).rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return 0


# general/fast 的存活候选。顺序即优先级，全部必须真的在监听才可用。
ROLE_EPS = {
    "general": ("127.0.0.1:2101", "127.0.0.1:2090", "127.0.0.1:2103"),
    "fast": ("127.0.0.1:2103", "127.0.0.1:2101", "127.0.0.1:2090"),
}
ANY_EPS = ("127.0.0.1:2101", "127.0.0.1:2103", "127.0.0.1:2090",
           "127.0.0.1:2096", "127.0.0.1:9910")


def live_eps():
    return [e for e in ANY_EPS if _port_open(ep_port(e))]


def resolve_ep(want, role):
    """把请求的出口换成一个真的在监听的出口；一个都没有时返回 None。

    general/fast 以前不做存活校验，而 hk/steam 做了。这个不对称是实发故障：
    autoroute.py --apply 无参调用 apply_pac() 会落到 DEFAULT_GENERAL=9910
    （Geph 未运行）和 DEFAULT_FAST=2086（pinned 配置里已无此 inbound），
    GENERAL 规则又是 fail-closed 不带 DIRECT，于是 claude.ai / anthropic.com
    在浏览器里硬断。2026-11-18 实测复现并修复。
    """
    if want and _port_open(ep_port(want)):
        return want
    for ep in ROLE_EPS.get(role, ()) + ANY_EPS:
        if _port_open(ep_port(ep)):
            return ep
    return None


def pac_endpoints(text):
    """从 PAC 文本里取出 GENERAL 规则实际用的两个端口，供内容级自愈比对。"""
    import re
    m = re.search(r'inList\(host,\s*GENERAL\)\)\s*return\s*"([^"]+)"', text or "")
    if not m:
        return None
    return tuple(re.findall(r"127\.0\.0\.1:(\d+)", m.group(1)))


def _served_bytes(port=PORT, timeout=2.0):
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/proxy.pac" % port,
                                    timeout=timeout) as r:
            return r.read(65536)
    except Exception:
        return None


def _serves_our_pac(port=PORT, timeout=2.0):
    """必须和本目录的 proxy.pac 逐字节一致。

    旧版只查 "FindProxyForURL" 字样：另一个目录里遗留的 pacroute
    服务（带着旧的 9910/2086 路由表）会冒充成"我们的"，端口被占住后
    新 PAC 永远发不出去——浏览器实际走的是旧表。2026-11-10 实发。
    """
    body = _served_bytes(port, timeout)
    if body is None:
        return False
    try:
        want = io.open(PAC_PATH, "rb").read()
    except OSError:
        return False
    return body == want


def server_alive(port=PORT):
    return _port_open(port) and _serves_our_pac(port)


def start_server(port=None):
    """返回真正在服务的端口（int）或 None。"""
    base = int(port or PORT)
    if server_alive(base):
        return base
    if _port_open(base):
        # 端口被别的（很可能是旧目录的）PAC 服务占着。它会在所有浏览器里
        # 悄悄服务一份旧路由表，所以让位换端口，而不是"看起来起来就行"。
        for alt in range(base + 1, base + 10):
            if server_alive(alt):
                return alt
            if not _port_open(alt):
                base = alt
                break
        else:
            return None
    os.makedirs(LOG_DIR, exist_ok=True)
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pyw if os.path.isfile(pyw) else sys.executable
    log = io.open(os.path.join(LOG_DIR, "pac_server.log"), "ab", buffering=0)
    p = subprocess.Popen([exe, os.path.abspath(__file__), "serve", str(base)],
                         stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                         creationflags=0x00000008 | 0x00000200)  # DETACHED | NEW_GROUP
    with io.open(PID_PATH, "w", encoding="utf-8") as f:
        f.write(str(p.pid))
    for _ in range(40):
        if server_alive(base):
            return base
        time.sleep(0.1)
    return None


def stop_server():
    if not os.path.isfile(PID_PATH):
        return
    try:
        pid = int(io.open(PID_PATH).read().strip())
    except Exception:
        return
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                       capture_output=True, timeout=10,
                       creationflags=0x08000000)
    except Exception:
        pass
    try:
        os.remove(PID_PATH)
    except OSError:
        pass


# ------------------------------------------------------------------ WinINET
def notify():
    try:
        import ctypes
        wininet = ctypes.WinDLL("wininet")
        wininet.InternetSetOptionW(0, 39, 0, 0)   # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)   # REFRESH
    except Exception:
        pass


def _wset(name, value, kind=winreg.REG_SZ):
    k = winreg.CreateKeyEx(K, IS, 0, winreg.KEY_ALL_ACCESS)
    try:
        winreg.SetValueEx(k, name, 0, kind, value)
    finally:
        k.Close()


def _wget(name):
    try:
        k = winreg.OpenKey(K, IS)
        try:
            return winreg.QueryValueEx(k, name)[0]
        finally:
            k.Close()
    except FileNotFoundError:
        return None


def load_dyn():
    """读 autoroute.py 产出的动态路由映射（没有就返回空，PAC 退回静态规则）。"""
    try:
        with io.open(os.path.join(HERE, "route_map.json"), encoding="utf-8") as f:
            return (json.load(f) or {}).get("groups") or {}
    except Exception:
        return {}


def apply_pac(general=DEFAULT_GENERAL, fast=DEFAULT_FAST, port=PORT, hk="auto", steam="auto",
              gai="auto"):
    want_general, want_fast = general, fast
    general = resolve_ep(general, "general")
    fast = resolve_ep(fast, "fast")
    if not general or not fast:
        # 一个本地出口都没活着。此时写 PAC 只会把 fail-closed 的 GENERAL 规则
        # 指向空端口，比保留旧表更糟——直接拒绝，让上层去重建出口。
        return {"ok": False, "err": "no live local exit (want general=%s fast=%s)"
                % (want_general, want_fast), "general": None, "fast": None}
    if hk == "auto":
        # 香港那条线只在监听时才写进 PAC；它挂了就退回下面两条
        hk = DEFAULT_HK if _port_open(ep_port(DEFAULT_HK)) else None
    if steam == "auto":
        steam = DEFAULT_STEAM if _port_open(ep_port(DEFAULT_STEAM)) else None
    if gai == "auto":
        # 2098 is the dedicated Google-AI exit started by 启动代理; only route to
        # it when it is actually listening, otherwise the PAC would send every
        # AI request into a dead port first.
        gai = DEFAULT_GAI if _port_open(ep_port(DEFAULT_GAI)) else None
    write_pac(general, fast, hk=hk, steam=steam, dyn=load_dyn(), gai=gai)
    actual = start_server(port)
    if not actual:
        return {"ok": False, "err": "PAC server 未起来（端口 %d-%d 均被占用？）"
                % (port, port + 9)}
    url = "http://127.0.0.1:%d/proxy.pac" % actual
    # Cache-buster.  Browsers keep a PAC until its URL changes, and the URL was
    # a constant, so a rule fix (e.g. adding aistudio.google.com) never reached
    # a browser that had already loaded the old table -- the site stayed broken
    # while every CLI probe returned 200.  A content hash makes the URL change
    # exactly when the rules change.
    try:
        h = hashlib.sha1(io.open(PAC_PATH, "rb").read()).hexdigest()[:8]
        url += "?v=" + h
    except OSError:
        pass
    try:
        with io.open(PAC_URL_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(url + "\n")
    except OSError:
        pass
    _wset("AutoConfigURL", url)
    # 静态代理（127.0.0.1:2090）是给不认 PAC 的下载器/UWP 用的，v3.0 起常开。
    # 这里若强制 ProxyEnable=0，看门狗每 10 分钟就把它写回来（日志里的
    # "static proxy entry missing/drifted -> re-apply"），两边拉锯。
    # PAC 存在时 WinINET 本来就优先用 PAC，静态值只是兜底，所以保留它。
    try:
        _k = winreg.OpenKey(K, IS, 0, winreg.KEY_READ)
        try:
            _srv = winreg.QueryValueEx(_k, "ProxyServer")[0]
        finally:
            _k.Close()
    except OSError:
        _srv = ""
    if not _srv:
        _wset("ProxyEnable", 0, winreg.REG_DWORD)
    notify()
    return {"ok": True, "url": url, "port": actual, "general": general, "fast": fast,
            "hk": hk, "steam": steam, "pac": PAC_PATH,
            "resolved_from": (want_general, want_fast)}


def clear_pac():
    try:
        k = winreg.OpenKey(K, IS, 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.DeleteValue(k, "AutoConfigURL")
        finally:
            k.Close()
    except FileNotFoundError:
        pass
    notify()
    stop_server()
    return True


def status():
    return {"pac_url": _wget("AutoConfigURL"),
            "proxy_enable": _wget("ProxyEnable"),
            "proxy_server": _wget("ProxyServer"),
            "server_alive": server_alive(),
            "pac_file": PAC_PATH}


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "serve":
        _serve_forever(int(argv[2]) if len(argv) > 2 else PORT)
        return 0
    if cmd == "apply":
        info = apply_pac()
        print(json.dumps(info, ensure_ascii=False, indent=1))
        return 0 if info.get("ok") else 1
    if cmd == "off":
        clear_pac()
        print("PAC cleared")
        return 0
    print(json.dumps(status(), ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
