package com.luhui.phoneproxy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * v2：内置节点（随 APK 打包）+ 用户导入节点（剪贴板 / 订阅链接）合并成一份 Xray 配置。
 *
 * 自动模式使用 Xray observatory + balancer(leastPing)：
 *   - 启动无需先测速，秒连；
 *   - 每 30s 并发探测全部节点，坏节点自动跳过，新连接自动选最快可用节点；
 *   - 节点随时失效也不用手动切。
 * 手动模式把默认路由固定到所选节点。
 */
public final class ConfigBuilder {

    public static final String PREFS = "imported";
    public static final String KEY_URIS = "uris";
    /** 上限：公开源一次能收进来一百多个，40 太小；120 条出站对 Xray 仍是轻松的。 */
    public static final int MAX_IMPORTED = 120;
    /** 单个源最多收多少条，避免一个巨型聚合列表把池子塞满。 */
    private static final int PER_SOURCE = 40;

    /**
     * 公开订阅源：仓库里只放 URL，**不含任何节点凭据**，运行时才去抓。
     * 每行 = {名字, 主地址, 镜像地址}。镜像是 jsDelivr 的 GitHub 加速，国内更容易连上；
     * 主地址与镜像都失败就跳过这一条，不影响其它源。
     * 这些是第三方公开聚合列表，节点质量与存活率不受本项目控制。
     */
    public static final String[][] PUBLIC_SOURCES = {
            {"barry-far",
             "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
             "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/All_Configs_Sub.txt"},
            {"mahdibland",
             "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
             "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge.txt"},
            {"ALIILAPRO",
             "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
             "https://cdn.jsdelivr.net/gh/ALIILAPRO/v2rayNG-Config@main/sub.txt"},
            {"peasoft",
             "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
             "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.txt"},
            {"ermaozi",
             "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
             "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/v2ray.txt"},
            {"aiboboxx",
             "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/sub",
             "https://cdn.jsdelivr.net/gh/aiboboxx/v2rayfree@main/sub"},
            {"ripaojiedian",
             "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
             "https://cdn.jsdelivr.net/gh/ripaojiedian/freenode@main/sub"},
    };


    /** loadNodes 跳过的条目（tag + 原因），供界面日志诊断用。 */
    public static final List<String> lastSkips = new ArrayList<>();

    public static final class Node {
        public final String tag;          // g3 / i0 ……（同时用于 proxy-<tag> 出站标签）
        public final String name;         // 展示名，如 "g3 · IT vless"
        public final boolean imported;
        public final boolean cg;          // 深测确认可过 ChatGPT 地区闸门
        public final JSONObject outbound; // tag 已改为 proxy-<tag>

        Node(String tag, String name, boolean imported, boolean cg, JSONObject outbound) {
            this.tag = tag;
            this.name = name;
            this.imported = imported;
            this.cg = cg;
            this.outbound = outbound;
        }
    }

    private ConfigBuilder() {}

    // ------------------------------------------------------------------ 加载

    /** 内置节点 + 导入节点。导入节点解析失败的直接跳过，不影响其它节点。 */
    public static List<Node> loadNodes(Context ctx) {
        List<Node> out = new ArrayList<>();
        lastSkips.clear();
        try {
            InputStream in = ctx.getAssets().open("nodes.json");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            JSONArray arr = new JSONArray(bos.toString("UTF-8"));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject item = arr.getJSONObject(i);
                String tag = item.getString("tag");
                JSONObject ob;
                if (item.has("outbound")) {
                    ob = item.getJSONObject("outbound");
                } else if (item.has("uri")) {
                    // 选线工具只挑节点、不实现协议，写原始分享链接，
                    // 由下面导入用的同一个 parseUri 解析，避免两套解析器漂移
                    ob = parseUri(item.getString("uri"));
                    if (ob == null) {
                        lastSkips.add(tag + " 无法解析");
                        continue;
                    }
                } else {
                    continue;
                }
                ob.put("tag", "proxy-" + tag);
                out.add(new Node(tag, item.optString("name", tag), false,
                        item.optBoolean("cg", false), ob));
            }
        } catch (Exception ignored) {
            // 内置节点坏了也要让导入节点能用
        }
        List<String> uris = loadImportedUris(ctx);
        int idx = 0;
        for (String uri : uris) {
            JSONObject ob;
            try {
                ob = parseUri(uri);
            } catch (Throwable t) {
                ob = null;
            }
            if (ob == null) {
                lastSkips.add("导入第 " + (idx + 1) + " 个无法解析");
                idx++;
                continue;
            }
            String tag = "i" + idx++;
            try {
                ob.put("tag", "proxy-" + tag);
            } catch (Exception e) {
                continue;
            }
            out.add(new Node(tag, tag + " · " + displayName(ob), true, false, ob));
        }
        return out;
    }

    /** 用标签查节点；找不到返回 null。 */
    public static Node find(List<Node> nodes, String tag) {
        for (Node n : nodes) if (n.tag.equals(tag)) return n;
        return null;
    }

    // ------------------------------------------------------------- 导入存储

    public static List<String> loadImportedUris(Context ctx) {
        List<String> out = new ArrayList<>();
        try {
            String raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .getString(KEY_URIS, "[]");
            JSONArray arr = new JSONArray(raw);
            for (int i = 0; i < arr.length(); i++) {
                String u = arr.optString(i, "").trim();
                if (!u.isEmpty()) out.add(u);
            }
        } catch (Exception ignored) {}
        return out;
    }

    public static void saveImportedUris(Context ctx, List<String> uris) {
        JSONArray arr = new JSONArray();
        for (String u : uris) arr.put(u);
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putString(KEY_URIS, arr.toString()).apply();
    }

    /** 合并导入（去重、限 40 条），返回新增条数。 */
    public static int addImportedUris(Context ctx, List<String> newUris) {
        LinkedHashSet<String> set = new LinkedHashSet<>(loadImportedUris(ctx));
        int before = set.size();
        for (String u : newUris) {
            u = u.trim();
            if (u.isEmpty()) continue;
            if (parseUri(u) == null) continue; // 只收能解析的
            set.add(u);
            if (set.size() >= MAX_IMPORTED) break;
        }
        List<String> merged = new ArrayList<>(set);
        saveImportedUris(ctx, merged);
        return Math.max(0, merged.size() - before);
    }

    /** 把一段文本拆成分享链接（支持多行/空格分隔；整段 base64 会先解码）。 */
    public static List<String> splitUris(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) return out;
        text = text.trim();
        if (text.isEmpty()) return out;
        if (!text.contains("://")) {
            String dec = tryB64(text);
            if (dec != null) text = dec;
        }
        for (String line : text.split("[\\s\\r\\n]+")) {
            if (line.contains("://")) out.add(line.trim());
        }
        return out;
    }

    /** 拉取订阅链接（在后台线程调用）。返回其中的分享链接。 */
    public static List<String> fetchSubscription(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(25000);
        c.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36");
        int code = c.getResponseCode();
        if (code != 200) throw new IllegalStateException("HTTP " + code);
        InputStream in = c.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n;
        int total = 0;
        while ((n = in.read(buf)) > 0) {
            total += n;
            // A hostile or broken subscription must not exhaust the phone's RAM
            // (review C11). 10 MB is far beyond any real share-link list.
            if (total > 10 * 1024 * 1024) {
                in.close();
                throw new IllegalStateException("subscription larger than 10 MB");
            }
            bos.write(buf, 0, n);
        }
        in.close();
        String body = bos.toString("UTF-8").trim();
        if (!body.contains("://")) {
            String dec = tryB64(body);
            if (dec != null) body = dec;
        }
        return splitUris(body);
    }

    /**
     * 抓取全部公开源（必须在后台线程调用）。每个源先走 GitHub raw，失败再走 jsDelivr 镜像。
     * log 收每个源的结果，供界面逐行显示；总数封顶 MAX_IMPORTED，单源封顶 PER_SOURCE。
     * 只收 parseUri 能解析的链接，避免把注释/广告行灌进节点池。
     */
    public static List<String> fetchPublicSources(List<String> log) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String[] s : PUBLIC_SOURCES) {
            if (out.size() >= MAX_IMPORTED) {
                log.add("已够 " + MAX_IMPORTED + " 条，后面的源不再抓");
                break;
            }
            String name = s[0];
            String[] urls = (s.length > 2 && s[2] != null && !s[2].isEmpty())
                    ? new String[]{s[1], s[2]} : new String[]{s[1]};
            boolean done = false;
            for (int i = 0; i < urls.length && !done; i++) {
                String tag = name + (urls.length > 1 && i == 1 ? "（镜像）" : "");
                try {
                    List<String> got = fetchSubscription(urls[i]);
                    int added = 0;
                    for (String u : got) {
                        if (added >= PER_SOURCE || out.size() >= MAX_IMPORTED) break;
                        if (parseUri(u) == null) continue;
                        if (out.add(u)) added++;
                    }
                    log.add(tag + "：" + got.size() + " 条，收下 " + added);
                    done = true;
                } catch (Exception e) {
                    log.add(tag + " 失败：" + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                }
            }
        }
        return new ArrayList<>(out);
    }

    // --------------------------------------------------------------- 配置

    /** 单节点测速配置（只有一个出站）。 */
    public static String measureConfig(Node node) throws Exception {
        JSONObject cfg = new JSONObject();
        cfg.put("log", new JSONObject().put("loglevel", "warning"));
        cfg.put("outbounds", new JSONArray().put(node.outbound));
        cfg.put("routing", new JSONObject()
                .put("domainStrategy", "IPIfNonMatch")
                .put("rules", new JSONArray()));
        return cfg.toString();
    }

    /**
     * 完整运行配置：TUN 入站 + 全部节点 + 直连 + DNS 出站。
     * selected = "auto" 走 observatory+balancer（leastPing），否则固定到该节点。
     */
    public static String fullConfig(List<Node> nodes, String selected) throws Exception {
        if (nodes.isEmpty()) throw new IllegalStateException("没有可用节点");

        JSONObject cfg = new JSONObject();
        cfg.put("log", new JSONObject().put("loglevel", "warning"));

        // DNS：国内域名走阿里 DNS（直连），其余走 Cloudflare DoH（经代理，防污染）
        JSONArray servers = new JSONArray();
        servers.put(new JSONObject()
                .put("address", "223.5.5.5")
                .put("domains", new JSONArray().put("geosite:cn"))
                .put("skipFallback", true));
        servers.put("https://1.1.1.1/dns-query");
        cfg.put("dns", new JSONObject()
                .put("servers", servers)
                .put("queryStrategy", "UseIPv4"));

        // TUN 入站：fd 由 startLoop(config, tunFd) 经环境变量传入
        JSONObject tun = new JSONObject()
                .put("tag", "tun-in")
                .put("protocol", "tun")
                .put("settings", new JSONObject().put("name", "xray0").put("mtu", 1500))
                .put("sniffing", new JSONObject()
                        .put("enabled", true)
                        .put("destOverride", new JSONArray().put("http").put("tls")));
        cfg.put("inbounds", new JSONArray().put(tun));

        JSONArray outbounds = new JSONArray();
        for (Node n : nodes) outbounds.put(n.outbound);
        outbounds.put(new JSONObject()
                .put("tag", "direct")
                .put("protocol", "freedom")
                .put("settings", new JSONObject().put("domainStrategy", "UseIPv4")));
        outbounds.put(new JSONObject().put("tag", "dns-out").put("protocol", "dns"));
        cfg.put("outbounds", outbounds);
        // 出站流量统计：不加这两个块，queryAllOutboundTrafficStats 永远返回空，
        // 界面上的 ↓/↑ 就一直是 0 B/s。
        cfg.put("stats", new JSONObject());
        cfg.put("policy", new JSONObject().put("system", new JSONObject()
                .put("statsInboundUplink", true)
                .put("statsInboundDownlink", true)
                .put("statsOutboundUplink", true)
                .put("statsOutboundDownlink", true)));

        JSONArray rules = new JSONArray();
        rules.put(rule().put("inboundTag", new JSONArray().put("tun-in"))
                .put("port", 53).put("outboundTag", "dns-out"));
        rules.put(rule().put("ip", new JSONArray().put("geoip:private"))
                .put("outboundTag", "direct"));
        // 2026-11-11 privacy: 敏感域（银行/支付/政务/社保/税务/教育）强制直连，
        // 绝不进免费节点——节点运营者能看到 TLS 目标域名，账号类站点不该出现在隧道里。
        JSONArray sensitive = new JSONArray();
        for (String d : SENSITIVE_DOMAINS) sensitive.put("domain:" + d);
        rules.put(rule().put("domain", sensitive).put("outboundTag", "direct"));
        // 2026-11-11 privacy: 明文 HTTP(80) 直连，避免节点看到明文 URL 与内容。
        rules.put(rule().put("port", 80).put("outboundTag", "direct"));
        rules.put(rule().put("domain", new JSONArray().put("geosite:cn"))
                .put("outboundTag", "direct"));
        rules.put(rule().put("ip", new JSONArray().put("geoip:cn"))
                .put("outboundTag", "direct"));

        JSONObject routing = new JSONObject().put("domainStrategy", "IPIfNonMatch");

        boolean auto = selected == null || selected.isEmpty() || "auto".equals(selected);
        Node sel = auto ? null : find(nodes, selected);
        if (auto || sel == null) {
            // ChatGPT / Claude 需要地区合格出口：内置节点里深测通过的成员
            // 各复制一份到 cg-* 前缀，单独组成 cg-balancer。普通流量用全部
            // 节点求最快，AI 域名只用合格池，两者都由 observatory 探活。
            int cgCount = 0;
            for (Node n : nodes) {
                if (!n.cg) continue;
                JSONObject copy = new JSONObject(n.outbound.toString());
                copy.put("tag", "cg-" + n.tag);
                outbounds.put(copy);
                cgCount++;
            }
            JSONArray subjects = new JSONArray().put("proxy-");
            JSONArray balancers = new JSONArray().put(new JSONObject()
                    .put("tag", "balancer")
                    .put("selector", new JSONArray().put("proxy-"))
                    .put("strategy", new JSONObject().put("type", "leastPing")));
            if (cgCount > 0) {
                subjects.put("cg-");
                balancers.put(new JSONObject()
                        .put("tag", "cg-balancer")
                        .put("selector", new JSONArray().put("cg-"))
                        .put("strategy", new JSONObject().put("type", "leastPing")));
            }
            cfg.put("observatory", new JSONObject()
                    .put("subjectSelector", subjects)
                    .put("probeUrl", "https://www.gstatic.com/generate_204")
                    .put("probeInterval", "30s")
                    .put("probeTimeout", "8s")
                    .put("enableConcurrency", true));
            routing.put("balancers", balancers);
            if (cgCount > 0) {
                rules.put(rule().put("network", "tcp,udp")
                        .put("domain", new JSONArray()
                                .put("domain:openai.com")
                                .put("domain:chatgpt.com")
                                .put("domain:oaistatic.com")
                                .put("domain:oaiusercontent.com")
                                .put("domain:anthropic.com")
                                .put("domain:claude.ai")
                                .put("domain:claude.com")
                                .put("domain:claudeusercontent.com"))
                        .put("balancerTag", "cg-balancer"));
            }
            rules.put(rule().put("network", "tcp,udp").put("balancerTag", "balancer"));
        } else {
            rules.put(rule().put("network", "tcp,udp")
                    .put("outboundTag", "proxy-" + sel.tag));
        }
        routing.put("rules", rules);
        cfg.put("routing", routing);
        return cfg.toString();
    }

    private static JSONObject rule() {
        return new JSONObject();
    }

    /** 2026-11-11 privacy: 敏感域名单（与 PC 端 pacroute.SENSITIVE 保持一致）。 */
    private static final String[] SENSITIVE_DOMAINS = {
            "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankofchina.com",
            "cmbchina.com", "bocom.cn", "psbc.com", "cmbc.com.cn", "spdb.com.cn",
            "ecitic.com", "cib.com.cn", "hxb.com.cn", "cgbchina.com.cn", "cebbank.com",
            "unionpay.com", "95516.com", "paypal.com", "alipay.com", "tenpay.com",
            "gov.cn", "chinatax.gov.cn", "12333.gov.cn", "12366.gov.cn", "pbc.gov.cn",
            "csrc.gov.cn", "nfra.gov.cn", "edu.cn", "si.12333.gov.cn",
    };

    // ---------------------------------------------------------- 分享链接解析

    /** 把一条分享链接解析成 Xray 出站（tag 未设置）。不支持/非法返回 null。 */
    public static JSONObject parseUri(String uri) {
        try {
            uri = uri == null ? "" : uri.trim();
            String lower = uri.toLowerCase();
            if (lower.startsWith("vless://")) return parseVless(uri.substring(8));
            if (lower.startsWith("vmess://")) return parseVmess(uri.substring(8));
            if (lower.startsWith("trojan://")) return parseTrojan(uri.substring(9));
            if (lower.startsWith("ss://")) return parseSs(uri.substring(5));
            if (lower.startsWith("socks://")) return parseSocksHttp(uri.substring(8), "socks");
            if (lower.startsWith("socks5://")) return parseSocksHttp(uri.substring(9), "socks");
            if (lower.startsWith("http://")) return parseSocksHttp(uri.substring(7), "http");
            // https:// share links mean "TLS to the proxy itself". Xray's HTTP
            // outbound has no client-side TLS, so treating it as plain http
            // would put the proxy credentials on the wire in clear (review C4).
            // Reject it and let the import log say "unsupported".
            if (lower.startsWith("https://")) return null;
        } catch (Throwable ignored) {}
        return null;
    }

    private static JSONObject parseVless(String body) throws Exception {
        body = stripFragment(body);
        String query = null;
        int qi = body.indexOf('?');
        if (qi >= 0) {
            query = body.substring(qi + 1);
            body = body.substring(0, qi);
        }
        int at = body.lastIndexOf('@');
        if (at <= 0) return null;
        String uuid = URLDecoder.decode(body.substring(0, at).trim(), "UTF-8");
        if (uuid.isEmpty()) return null;
        String[] hp = splitHostPort(body.substring(at + 1));
        if (hp == null) return null;
        Map<String, String> q = parseQuery(query);

        JSONObject user = new JSONObject().put("id", uuid)
                .put("encryption", q.containsKey("encryption") ? q.get("encryption") : "none");
        if (q.containsKey("flow") && !q.get("flow").isEmpty()) user.put("flow", q.get("flow"));
        JSONObject vnext = new JSONObject()
                .put("address", hp[0]).put("port", Integer.parseInt(hp[1]))
                .put("users", new JSONArray().put(user));
        JSONObject ob = new JSONObject()
                .put("protocol", "vless")
                .put("settings", new JSONObject().put("vnext", new JSONArray().put(vnext)));
        ob.put("streamSettings", streamSettings(q));
        return ob;
    }

    private static JSONObject parseVmess(String body) throws Exception {
        body = stripFragment(body);
        String json = tryB64(body);
        if (json == null) return null;
        JSONObject v = new JSONObject(json);
        String host = v.getString("add").trim();
        int port = v.getInt("port");
        String id = v.getString("id").trim();
        if (host.isEmpty() || id.isEmpty()) return null;
        JSONObject user = new JSONObject()
                .put("id", id)
                .put("alterId", v.optInt("aid", 0))
                .put("security", v.optString("scy", "auto"));
        JSONObject vnext = new JSONObject()
                .put("address", host).put("port", port)
                .put("users", new JSONArray().put(user));
        JSONObject ob = new JSONObject()
                .put("protocol", "vmess")
                .put("settings", new JSONObject().put("vnext", new JSONArray().put(vnext)));

        Map<String, String> q = new HashMap<>();
        String net = v.optString("net", "tcp");
        q.put("type", net);
        q.put("headerType", v.optString("type", "none"));
        q.put("host", v.optString("host", ""));
        q.put("path", v.optString("path", "/"));
        q.put("sni", v.optString("sni", ""));
        q.put("fp", v.optString("fp", "chrome"));
        q.put("alpn", v.optString("alpn", ""));
        boolean tls = "tls".equals(v.optString("tls", ""));
        q.put("security", tls ? "tls" : "none");
        if (tls && q.get("sni").isEmpty()) q.put("sni", q.get("host"));
        if ("grpc".equals(net)) q.put("serviceName", v.optString("path", ""));
        ob.put("streamSettings", streamSettings(q));
        return ob;
    }

    private static JSONObject parseTrojan(String body) throws Exception {
        body = stripFragment(body);
        String query = null;
        int qi = body.indexOf('?');
        if (qi >= 0) {
            query = body.substring(qi + 1);
            body = body.substring(0, qi);
        }
        int at = body.lastIndexOf('@');
        if (at <= 0) return null;
        String password = URLDecoder.decode(body.substring(0, at).trim(), "UTF-8");
        String[] hp = splitHostPort(body.substring(at + 1));
        if (hp == null || password.isEmpty()) return null;
        Map<String, String> q = parseQuery(query);
        if (!q.containsKey("security") || q.get("security").isEmpty()) q.put("security", "tls");
        JSONObject server = new JSONObject()
                .put("address", hp[0]).put("port", Integer.parseInt(hp[1]))
                .put("password", password);
        JSONObject ob = new JSONObject()
                .put("protocol", "trojan")
                .put("settings", new JSONObject().put("servers", new JSONArray().put(server)));
        ob.put("streamSettings", streamSettings(q));
        return ob;
    }

    private static JSONObject parseSs(String body) throws Exception {
        body = stripFragment(body);
        // 带插件的一律不支持（Xray 无 plugins）
        if (body.contains("plugin=")) return null;
        String method, password;
        String hostPort;
        int at = body.lastIndexOf('@');
        if (at > 0) {
            String userinfo = body.substring(0, at);
            hostPort = body.substring(at + 1);
            String decoded = tryB64(userinfo);
            if (decoded == null || !decoded.contains(":")) {
                decoded = URLDecoder.decode(userinfo, "UTF-8");
            }
            int c = decoded.indexOf(':');
            if (c <= 0) return null;
            method = decoded.substring(0, c).trim();
            password = decoded.substring(c + 1);
        } else {
            String decoded = tryB64(body);
            if (decoded == null) return null;
            int c = decoded.indexOf(':');
            int a = decoded.lastIndexOf('@');
            if (c <= 0 || a <= c) return null;
            method = decoded.substring(0, c).trim();
            password = decoded.substring(c + 1, a);
            hostPort = decoded.substring(a + 1);
        }
        if (!SS_CIPHERS.contains(method)) return null;
        String[] hp = splitHostPort(hostPort);
        if (hp == null) return null;
        JSONObject server = new JSONObject()
                .put("address", hp[0]).put("port", Integer.parseInt(hp[1]))
                .put("method", method).put("password", password);
        return new JSONObject()
                .put("protocol", "shadowsocks")
                .put("settings", new JSONObject().put("servers", new JSONArray().put(server)));
    }

    private static JSONObject parseSocksHttp(String body, String proto) throws Exception {
        body = stripFragment(body);
        int qi = body.indexOf('?');   // 分享链接带的 ?tls=true 等装饰参数，Xray http/socks 出站不认
        if (qi >= 0) body = body.substring(0, qi);
        int slash = body.indexOf('/'); // http://host:port/ 这种尾路径
        if (slash >= 0) body = body.substring(0, slash);
        String user = "", pass = "";
        int at = body.lastIndexOf('@');
        if (at >= 0) {
            String ui = URLDecoder.decode(body.substring(0, at), "UTF-8");
            body = body.substring(at + 1);
            int c = ui.indexOf(':');
            if (c >= 0) {
                user = ui.substring(0, c);
                pass = ui.substring(c + 1);
            } else {
                user = ui;
            }
        }
        String[] hp = splitHostPort(body);
        if (hp == null) return null;
        JSONObject server = new JSONObject()
                .put("address", hp[0]).put("port", Integer.parseInt(hp[1]));
        if (!user.isEmpty()) {
            server.put("users", new JSONArray().put(
                    new JSONObject().put("user", user).put("pass", pass)));
        }
        return new JSONObject()
                .put("protocol", proto)
                .put("settings", new JSONObject().put("servers", new JSONArray().put(server)));
    }

    private static final LinkedHashSet<String> SS_CIPHERS = new LinkedHashSet<>();

    static {
        String[] c = {
                "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
                "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-poly1305",
                "xchacha20-ietf-poly1305", "chacha20", "chacha20-ietf",
                "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                "2022-blake3-chacha20-poly1305",
                "none", "plain", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
                "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        };
        for (String s : c) SS_CIPHERS.add(s);
    }

    private static JSONObject streamSettings(Map<String, String> q) throws Exception {
        String net = q.containsKey("type") && !q.get("type").isEmpty() ? q.get("type") : "tcp";
        String sec = q.containsKey("security") && !q.get("security").isEmpty()
                ? q.get("security") : "none";
        JSONObject ss = new JSONObject();
        ss.put("network", net);

        if ("reality".equals(sec)) {
            ss.put("security", "reality");
            JSONObject r = new JSONObject();
            r.put("serverName", q.containsKey("sni") ? q.get("sni") : "");
            r.put("fingerprint", q.containsKey("fp") && !q.get("fp").isEmpty()
                    ? q.get("fp") : "chrome");
            r.put("publicKey", q.containsKey("pbk") ? q.get("pbk") : "");
            r.put("shortId", q.containsKey("sid") ? q.get("sid") : "");
            r.put("spiderX", q.containsKey("spx") && !q.get("spx").isEmpty()
                    ? q.get("spx") : "/");
            ss.put("realitySettings", r);
        } else if ("tls".equals(sec)) {
            ss.put("security", "tls");
            JSONObject t = new JSONObject();
            String sni = q.containsKey("sni") ? q.get("sni") : "";
            if (sni.isEmpty() && q.containsKey("host")) sni = q.get("host");
            if (!sni.isEmpty()) t.put("serverName", sni);
            t.put("fingerprint", q.containsKey("fp") && !q.get("fp").isEmpty()
                    ? q.get("fp") : "chrome");
            String alpn = q.containsKey("alpn") ? q.get("alpn") : "";
            if (!alpn.isEmpty()) {
                JSONArray a = new JSONArray();
                for (String x : alpn.split(",")) {
                    x = x.trim();
                    if (!x.isEmpty()) a.put(x);
                }
                t.put("alpn", a);
            }
            String insecure = q.containsKey("allowInsecure") ? q.get("allowInsecure") : "0";
            t.put("allowInsecure", "1".equals(insecure) || "true".equals(insecure));
            ss.put("tlsSettings", t);
        } else {
            ss.put("security", "none");
        }

        if ("ws".equals(net)) {
            JSONObject w = new JSONObject().put("path",
                    q.containsKey("path") && !q.get("path").isEmpty() ? q.get("path") : "/");
            String host = q.containsKey("host") ? q.get("host") : "";
            if (!host.isEmpty()) w.put("headers", new JSONObject().put("Host", host));
            ss.put("wsSettings", w);
        } else if ("grpc".equals(net)) {
            ss.put("grpcSettings", new JSONObject()
                    .put("serviceName", q.containsKey("serviceName") ? q.get("serviceName") : "")
                    .put("multiMode", "multi".equals(q.containsKey("mode") ? q.get("mode") : "gun")));
        } else if ("httpupgrade".equals(net)) {
            JSONObject h = new JSONObject().put("path",
                    q.containsKey("path") && !q.get("path").isEmpty() ? q.get("path") : "/");
            String host = q.containsKey("host") ? q.get("host") : "";
            if (!host.isEmpty()) h.put("host", host);
            ss.put("httpupgradeSettings", h);
        } else if ("h2".equals(net)) {
            JSONObject h = new JSONObject().put("path",
                    q.containsKey("path") && !q.get("path").isEmpty() ? q.get("path") : "/");
            String host = q.containsKey("host") ? q.get("host") : "";
            if (!host.isEmpty()) h.put("host", new JSONArray().put(host));
            ss.put("httpSettings", h);
        } else if ("tcp".equals(net)
                && "http".equals(q.containsKey("headerType") ? q.get("headerType") : "none")) {
            ss.put("tcpSettings", new JSONObject().put("header",
                    new JSONObject().put("type", "http")));
        }
        return ss;
    }

    // ------------------------------------------------------------- 小工具

    private static String stripFragment(String s) {
        int h = s.indexOf('#');
        return h >= 0 ? s.substring(0, h) : s;
    }

    private static String[] splitHostPort(String hp) {
        hp = hp.trim();
        if (hp.isEmpty()) return null;
        try {
            if (hp.startsWith("[")) {
                int e = hp.indexOf(']');
                if (e < 0) return null;
                String host = hp.substring(1, e);
                int c = hp.indexOf(':', e);
                int port = c < 0 ? 443 : Integer.parseInt(hp.substring(c + 1));
                return new String[]{host, String.valueOf(port)};
            }
            int c = hp.lastIndexOf(':');
            if (c <= 0) return new String[]{hp, "443"};
            String host = hp.substring(0, c);
            int port = Integer.parseInt(hp.substring(c + 1));
            if (port <= 0 || port > 65535) return null;
            return new String[]{host, String.valueOf(port)};
        } catch (Exception e) {
            return null;
        }
    }

    private static Map<String, String> parseQuery(String q) throws Exception {
        Map<String, String> m = new HashMap<>();
        if (q == null || q.isEmpty()) return m;
        for (String kv : q.split("&")) {
            if (kv.isEmpty()) continue;
            int i = kv.indexOf('=');
            String k = i < 0 ? kv : kv.substring(0, i);
            String v = i < 0 ? "" : kv.substring(i + 1);
            m.put(URLDecoder.decode(k, "UTF-8"), URLDecoder.decode(v, "UTF-8"));
        }
        return m;
    }

    /** 宽松 base64 解码（URL-safe / 缺 padding / 带换行都认）。失败返回 null。 */
    static String tryB64(String s) {
        if (s == null) return null;
        s = s.trim().replace("\r", "").replace("\n", "").replace(" ", "");
        if (s.isEmpty()) return null;
        s = s.replace('-', '+').replace('_', '/');
        int pad = (4 - s.length() % 4) % 4;
        for (int i = 0; i < pad; i++) s += "=";
        try {
            byte[] b = android.util.Base64.decode(s, android.util.Base64.DEFAULT);
            String out = new String(b, "UTF-8");
            return out.isEmpty() ? null : out;
        } catch (Throwable e) {
            return null;
        }
    }

    private static String displayName(JSONObject ob) {
        try {
            String proto = ob.optString("protocol", "?");
            JSONObject st = ob.optJSONObject("settings");
            String host = "?";
            if (st != null) {
                JSONArray arr = st.optJSONArray("vnext");
                if (arr == null) arr = st.optJSONArray("servers");
                if (arr != null && arr.length() > 0) {
                    host = arr.getJSONObject(0).optString("address", "?");
                }
            }
            return proto + " " + host;
        } catch (Exception e) {
            return "?";
        }
    }
}
