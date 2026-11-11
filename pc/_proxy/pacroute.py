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
import io
import json
import os
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
]
STEAM_DIRECT = ["steamcontent.com", "steamcdn-a.akamaihd.net"]
DIRECT += STEAM_DIRECT
DEFAULT_STEAM = "127.0.0.1:2096"      # 美国出口（sing-box，start_proxy 负责拉起）
# 实测只有香港那条线能过（fast/general/geph 全是 403 "blocked by network security"）
HK = ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
      "redditinc.com", "reddithelp.com"]


def _js_list(name, domains):
    arr = ", ".join('"%s"' % d for d in domains)
    return "var %s = [%s];" % (name, arr)


def render_pac(general=DEFAULT_GENERAL, fast=DEFAULT_FAST, stamp=None, hk=None, steam=None):
    stamp = stamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    gh, gp = general.rsplit(":", 1)
    fh, fp = fast.rsplit(":", 1)
    steam_rule = ""
    steam_vars = "var STEAM = [];"
    if steam:
        steam_vars = _js_list("STEAM", STEAM)
        steam_rule = ('  if (inList(host, STEAM))     return "PROXY %(steam)s; PROXY %(fast)s; '
                      'PROXY %(general)s; DIRECT";\n' % {"steam": steam, "fast": fast,
                                                        "general": general})
    hk_rule = ""
    hk_vars = "var HK = [];"
    if hk:
        hh, hp = hk.rsplit(":", 1)
        hk_vars = _js_list("HK", HK)
        hk_rule = ('  if (inList(host, HK))       return "PROXY %(hk)s; PROXY %(fast)s; '
                   'PROXY %(general)s; DIRECT";\n' % {"hk": hk, "fast": fast,
                                                     "general": general})
    return """// split-routing PAC · generated %(stamp)s
// general(OpenAI/Claude) -> %(general)s   fast(Google/GitHub/HF) -> %(fast)s
// hk(reddit 专用) -> %(hk)s
%(dom)s
%(sens_d)s
%(fast_d)s
%(gen_d)s
%(hk_d)s
%(steam_d)s
%(direct_d)s

function dom(h, d) { return h === d || dnsDomainIs(h, "." + d); }

function inList(h, list) {
  for (var i = 0; i < list.length; i++) { if (dom(h, list[i])) return true; }
  return false;
}

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" ||
      isPlainHostName(host) || shExpMatch(host, "127.*") ||
      shExpMatch(host, "192.168.*") || shExpMatch(host, "10.*") ||
      shExpMatch(host, "172.1[6-9].*") || shExpMatch(host, "172.2[0-9].*") ||
      shExpMatch(host, "172.3[0-1].*")) {
    return "DIRECT";
  }
  if (inList(host, DOMESTIC)) return "DIRECT";
  if (inList(host, SENSITIVE)) return "DIRECT";
  if (inList(host, DIRECT))   return "DIRECT";
%(steam_rule)s%(hk_rule)s  if (inList(host, FAST))     return "PROXY %(fast)s; PROXY %(general)s; DIRECT";
  if (inList(host, GENERAL))  return "PROXY %(general)s; PROXY %(fast)s; DIRECT";
  // 默认先走快出口（Google/GitHub/HF 等已验证可过），它打不开时再退回通用出口
  return "PROXY %(fast)s; PROXY %(general)s; DIRECT";
}
""" % {
        "stamp": stamp,
        "general": general,
        "fast": fast,
        "hk": hk or "",
        "hk_rule": hk_rule,
        "dom": _js_list("DOMESTIC", DOMESTIC),
        "sens_d": _js_list("SENSITIVE", SENSITIVE),
        "fast_d": _js_list("FAST", FAST),
        "gen_d": _js_list("GENERAL", GENERAL),
        "hk_d": hk_vars,
        "steam_d": steam_vars,
        "steam_rule": steam_rule,
        "direct_d": _js_list("DIRECT", DIRECT),
    }


def write_pac(general=DEFAULT_GENERAL, fast=DEFAULT_FAST, hk=None, steam=None):
    text = render_pac(general, fast, hk=hk, steam=steam)
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
    srv.serve_forever()


def _port_open(port=PORT):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


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


def apply_pac(general=DEFAULT_GENERAL, fast=DEFAULT_FAST, port=PORT, hk="auto", steam="auto"):
    if hk == "auto":
        # 香港那条线只在监听时才写进 PAC；它挂了就退回下面两条
        hk = DEFAULT_HK if _port_open(int(DEFAULT_HK.rsplit(":", 1)[1])) else None
    if steam == "auto":
        steam = DEFAULT_STEAM if _port_open(int(DEFAULT_STEAM.rsplit(":", 1)[1])) else None
    write_pac(general, fast, hk=hk, steam=steam)
    actual = start_server(port)
    if not actual:
        return {"ok": False, "err": "PAC server 未起来（端口 %d-%d 均被占用？）"
                % (port, port + 9)}
    url = "http://127.0.0.1:%d/proxy.pac" % actual
    try:
        with io.open(PAC_URL_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(url + "\n")
    except OSError:
        pass
    _wset("AutoConfigURL", url)
    _wset("ProxyEnable", 0, winreg.REG_DWORD)
    notify()
    return {"ok": True, "url": url, "port": actual, "general": general, "fast": fast,
            "hk": hk, "steam": steam, "pac": PAC_PATH}


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
