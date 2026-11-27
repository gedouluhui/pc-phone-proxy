package com.luhui.phoneproxy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 分享链接 -> Xray 出站 / 完整配置的纯 Java 实现。
 *
 * <p>这里刻意不引用任何 android.* 类：同一个文件既编进 APK，也被
 * {@code phone/tests/PoisonHarness.java} 和 {@code phone/tools/check_poison.py}
 * 用普通 JDK 编译，喂真实 Xray 二进制做「解析出的配置一定能被内核接受」的闭环。
 * 之前的手写规则和内核真实行为多次漂移（明文 VLESS、QUIC 传输、旧版 SS 加密
 * 都是整份配置直接拒绝），所以规则以 Xray v26.11.9 实测为准写在这里。
 *
 * <p>解析阶段的取舍：
 * - 宁可少收：任何会让整份运行配置报错的字段都在这里拦掉，一条坏链接不能拖死
 *   整个节点池。
 * - 不信任导入内容：私网/回环地址、allowInsecure、未知传输/加密/指纹一律不采纳。
 */
public final class NodeConfigCodec {

    private NodeConfigCodec() {
    }

    /** 单条分享链接的上限：订阅里偶尔混进整段 base64，防止一次解析吃掉内存。 */
    public static final int MAX_URI_LENGTH = 8192;

    private static final Charset UTF8 = Charset.forName("UTF-8");

    /** Xray 26 已移除 http/h2、quic 传输；mkcp 是 kcp 的别名。 */
    private static final Set<String> SUPPORTED_NET = new HashSet<>(Arrays.asList(
            "tcp", "raw", "ws", "grpc", "xhttp", "kcp", "mkcp", "httpupgrade"));

    /**
     * Xray 26 实际接受的 Shadowsocks 方法（逐个用 xray run -test 验过）。
     * 已移除 chacha20/chacha20-ietf/CFB/CTR/none/plain/aes-192-gcm 等旧方法。
     */
    private static final Set<String> SS_CIPHERS = new LinkedHashSet<>(Arrays.asList(
            "aes-128-gcm", "aes-256-gcm",
            "chacha20-poly1305", "chacha20-ietf-poly1305",
            "xchacha20-poly1305", "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305"));

    /** uTLS 指纹白名单；写错一个字母 Xray 就拒绝整份配置。 */
    private static final Set<String> UTLS_FINGERPRINTS = new HashSet<>(Arrays.asList(
            "chrome", "firefox", "safari", "ios", "android", "edge",
            "360", "qq", "random", "randomized", "hellogolang"));

    /** 目前只有这两种 flow 能被 Xray 26 接受。 */
    private static final Set<String> FLOWS = new HashSet<>(Arrays.asList(
            "xtls-rprx-vision", "xtls-rprx-vision-udp443"));

    private static final Set<String> XHTTP_MODES = new HashSet<>(Arrays.asList(
            "auto", "packet-up", "stream-up", "stream-one"));

    // ---------------------------------------------------------- 分享链接解析

    /** 把一条分享链接解析成 Xray 出站（tag 未设置）。不支持/非法返回 null。 */
    public static JSONObject parseUri(String uri) {
        try {
            uri = uri == null ? "" : uri.trim();
            if (uri.isEmpty() || uri.length() > MAX_URI_LENGTH) return null;
            String lower = uri.toLowerCase(Locale.ROOT);
            if (lower.startsWith("vless://")) return parseVless(uri.substring(8));
            if (lower.startsWith("vmess://")) return parseVmess(uri.substring(8));
            if (lower.startsWith("trojan://")) return parseTrojan(uri.substring(9));
            if (lower.startsWith("ss://")) return parseSs(uri.substring(5));
            if (lower.startsWith("hysteria2://")) return parseHysteria2(uri.substring(12));
            if (lower.startsWith("hy2://")) return parseHysteria2(uri.substring(6));
            if (lower.startsWith("socks://")) return parseSocksHttp(uri.substring(8), "socks");
            if (lower.startsWith("socks5://")) return parseSocksHttp(uri.substring(9), "socks");
            if (lower.startsWith("http://")) return parseSocksHttp(uri.substring(7), "http");
            // https:// 分享链接表示「到代理本身用 TLS」。Xray 的 HTTP 出站没有
            // 客户端 TLS，当明文 http 处理会把代理密码发到线上，所以直接拒绝。
            if (lower.startsWith("https://")) return null;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static JSONObject parseVless(String body) {
        body = stripFragment(body);
        String query = null;
        int qi = body.indexOf('?');
        if (qi >= 0) {
            query = body.substring(qi + 1);
            body = body.substring(0, qi);
        }
        int at = body.lastIndexOf('@');
        if (at <= 0) return null;
        String uuid = percentDecode(body.substring(0, at).trim());
        if (!validUserId(uuid)) return null;
        String[] hp = splitHostPort(body.substring(at + 1));
        if (hp == null) return null;
        if (!isAllowedNodeHost(hp[0])) return null;

        Map<String, String> q = parseQuery(query);
        if (q == null) return null;

        // Xray 26 禁止明文 VLESS（"vless without TLS or other encryption is
        // prohibited..."）。VLESS Encryption 的密钥语法这里不实现，带非 none
        // encryption 的链接也拒绝，避免猜错格式拖死整份配置。
        String sec = lower(qstr(q, "security", "none"));
        if (!"tls".equals(sec) && !"reality".equals(sec)) return null;
        String enc = qstr(q, "encryption", "none");
        if (!"none".equalsIgnoreCase(enc) || hasControl(enc)) return null;

        String flow = qstr(q, "flow", "").trim();
        if (!flow.isEmpty() && !FLOWS.contains(flow)) return null;
        try {
            JSONObject user = new JSONObject().put("id", uuid).put("encryption", "none");
            if (!flow.isEmpty()) user.put("flow", flow);
            JSONObject vnext = new JSONObject()
                    .put("address", hp[0]).put("port", Integer.parseInt(hp[1]))
                    .put("users", new JSONArray().put(user));
            JSONObject stream = streamSettings(q);
            if (stream == null) return null;
            return new JSONObject()
                    .put("protocol", "vless")
                    .put("settings", new JSONObject().put("vnext", new JSONArray().put(vnext)))
                    .put("streamSettings", stream);
        } catch (Exception error) {
            return null;
        }
    }

    private static JSONObject parseVmess(String body) {
        body = stripFragment(body);
        String json = tryB64(body);
        if (json == null) return null;
        JSONObject v;
        try {
            v = new JSONObject(json);
        } catch (Exception error) {
            return null;
        }
        String host = str(v, "add");
        int port = intValue(v.opt("port"), -1);
        String id = str(v, "id");
        if (host.isEmpty() || !validUserId(id) || port < 1 || port > 65535) return null;
        if (!isAllowedNodeHost(host)) return null;

        try {
            JSONObject user = new JSONObject()
                    .put("id", id)
                    .put("alterId", intValue(v.opt("aid"), 0))
                    .put("security", nonEmpty(str(v, "scy"), "auto"));
            JSONObject vnext = new JSONObject()
                    .put("address", host).put("port", port)
                    .put("users", new JSONArray().put(user));

            String net = lower(nonEmpty(str(v, "net"), "tcp"));
            String tls = lower(str(v, "tls"));
            Map<String, String> q = new HashMap<>();
            q.put("type", net);
            q.put("headerType", nonEmpty(str(v, "type"), "none"));
            q.put("host", str(v, "host"));
            q.put("path", nonEmpty(str(v, "path"), "/"));
            q.put("sni", str(v, "sni"));
            q.put("fp", str(v, "fp"));
            q.put("alpn", str(v, "alpn"));
            q.put("security", "tls".equals(tls) || "reality".equals(tls) ? tls : "none");
            if ("reality".equals(tls)) {
                q.put("pbk", str(v, "pbk"));
                q.put("sid", str(v, "sid"));
            }
            if (!"none".equals(tls) && q.get("sni").isEmpty()) q.put("sni", q.get("host"));
            if ("grpc".equals(net)) q.put("serviceName", q.get("path"));
            JSONObject stream = streamSettings(q);
            if (stream == null) return null;
            return new JSONObject()
                    .put("protocol", "vmess")
                    .put("settings", new JSONObject().put("vnext", new JSONArray().put(vnext)))
                    .put("streamSettings", stream);
        } catch (Exception error) {
            return null;
        }
    }

    private static JSONObject parseTrojan(String body) {
        body = stripFragment(body);
        String query = null;
        int qi = body.indexOf('?');
        if (qi >= 0) {
            query = body.substring(qi + 1);
            body = body.substring(0, qi);
        }
        int at = body.lastIndexOf('@');
        if (at <= 0) return null;
        String password = percentDecode(body.substring(0, at).trim());
        if (password == null || password.isEmpty() || hasControl(password)) return null;
        String[] hp = splitHostPort(body.substring(at + 1));
        if (hp == null) return null;
        if (!isAllowedNodeHost(hp[0])) return null;
        Map<String, String> q = parseQuery(query);
        if (q == null) return null;
        // Xray 26 同样禁止明文 trojan（只放行私网/本机地址，而这两类我们本来就拒收）。
        String sec = lower(qstr(q, "security", "tls"));
        if (!"tls".equals(sec) && !"reality".equals(sec)) return null;
        q.put("security", sec);
        try {
            JSONObject server = new JSONObject()
                    .put("address", hp[0]).put("port", Integer.parseInt(hp[1]))
                    .put("password", password);
            JSONObject stream = streamSettings(q);
            if (stream == null) return null;
            return new JSONObject()
                    .put("protocol", "trojan")
                    .put("settings", new JSONObject().put("servers", new JSONArray().put(server)))
                    .put("streamSettings", stream);
        } catch (Exception error) {
            return null;
        }
    }

    private static JSONObject parseSs(String body) {
        body = stripFragment(body);
        if (body.contains("plugin=")) return null;
        String method;
        String password;
        String hostPort;
        int at = body.lastIndexOf('@');
        if (at > 0) {
            String userinfo = body.substring(0, at);
            hostPort = body.substring(at + 1);
            String decoded = tryB64(userinfo);
            if (decoded == null || !decoded.contains(":")) {
                decoded = percentDecode(userinfo);
            }
            if (decoded == null) return null;
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
        method = lower(method);
        if (!SS_CIPHERS.contains(method)) return null;
        if (password == null || password.isEmpty() || hasControl(password)) return null;
        // SS2022 的 PSK 是定长 base64，截断/空格都会让 core init 直接拒绝整份配置。
        if (method.startsWith("2022-")) {
            int want = method.contains("aes-128") ? 16 : 32;
            if (!validSs2022Key(password, want)) return null;
        }
        String[] hp = splitHostPort(hostPort);
        if (hp == null || !isAllowedNodeHost(hp[0])) return null;
        try {
            JSONObject server = new JSONObject()
                    .put("address", hp[0]).put("port", Integer.parseInt(hp[1]))
                    .put("method", method).put("password", password);
            return new JSONObject()
                    .put("protocol", "shadowsocks")
                    .put("settings", new JSONObject().put("servers", new JSONArray().put(server)));
        } catch (Exception error) {
            return null;
        }
    }

    /**
     * v3.1：Hysteria2（{@code hysteria2://auth@host:port/?sni=&obfs=salamander&obfs-password=&mport=}）。
     *
     * <p>Xray 26 的写法是 {@code protocol=hysteria}（version 2）+ {@code network=hysteria} 传输 +
     * 强制 TLS（ALPN h3）；salamander 混淆放在 {@code finalmask.udp}，端口跳跃放在
     * {@code finalmask.quicParams.udpHop}。QUIC 走 UDP，在大陆的可达性和速度经常比 TCP 节点好。
     *
     * <p>{@code insecure=1} 与 {@code pinSHA256} 不采纳：与其它导入节点一致，证书必须能校验，
     * 自签名节点会在本机实测阶段被筛掉，而不是静默放行中间人。
     */
    private static JSONObject parseHysteria2(String body) {
        body = stripFragment(body);
        String query = null;
        int qi = body.indexOf('?');
        if (qi >= 0) {
            query = body.substring(qi + 1);
            body = body.substring(0, qi);
        }
        int at = body.lastIndexOf('@');
        if (at <= 0) return null;
        String auth = percentDecode(body.substring(0, at).trim());
        if (auth == null || auth.isEmpty() || auth.length() > 512 || hasControl(auth)) return null;
        String hostPort = body.substring(at + 1).trim();
        int slash = hostPort.indexOf('/');
        if (slash >= 0) hostPort = hostPort.substring(0, slash);
        String host;
        String portSpec;
        if (hostPort.startsWith("[")) {
            int e = hostPort.indexOf(']');
            if (e < 0) return null;
            host = hostPort.substring(1, e);
            String rest = hostPort.substring(e + 1);
            if (rest.isEmpty()) portSpec = "443";
            else if (rest.startsWith(":")) portSpec = rest.substring(1);
            else return null;
        } else {
            int c = hostPort.lastIndexOf(':');
            if (c < 0) {
                host = hostPort;
                portSpec = "443";
            } else {
                host = hostPort.substring(0, c);
                portSpec = hostPort.substring(c + 1);
            }
            if (host.indexOf(':') >= 0) return null; // 裸 IPv6 必须带方括号
        }
        host = host.trim();
        portSpec = portSpec.trim();
        if (host.isEmpty() || !isAllowedNodeHost(host)) return null;
        Map<String, String> q = parseQuery(query);
        if (q == null) return null;

        String hop = null;
        int port;
        if (portSpec.matches("\\d{1,5}")) {
            port = Integer.parseInt(portSpec);
        } else if (validPortSpec(portSpec)) {
            // 443,20000-30000 这种写法：先连第一个端口，其余交给端口跳跃
            port = Integer.parseInt(portSpec.split("[,-]")[0]);
            hop = portSpec;
        } else {
            return null;
        }
        if (port < 1 || port > 65535) return null;
        String mport = qstr(q, "mport", "").trim();
        if (hop == null && !mport.isEmpty()) {
            if (!validPortSpec(mport)) return null;
            hop = mport;
        }

        String sni = qstr(q, "sni", "").trim();
        if (sni.isEmpty()) sni = qstr(q, "peer", "").trim();
        if (hasControl(sni) || sni.length() > 253) return null;
        String obfs = lower(qstr(q, "obfs", "").trim());
        String obfsPassword = qstr(q, "obfs-password", "");
        boolean salamander = false;
        if (!obfs.isEmpty() && !"none".equals(obfs)) {
            if (!"salamander".equals(obfs)) return null;
            if (obfsPassword.isEmpty() || obfsPassword.length() > 512 || hasControl(obfsPassword)) {
                return null;
            }
            salamander = true;
        }
        try {
            JSONObject tls = new JSONObject();
            if (!sni.isEmpty()) tls.put("serverName", sni);
            else if (!isIpLiteral(host)) tls.put("serverName", host);
            tls.put("alpn", new JSONArray().put("h3"));
            tls.put("allowInsecure", false);
            JSONObject stream = new JSONObject()
                    .put("network", "hysteria")
                    .put("security", "tls")
                    .put("tlsSettings", tls)
                    .put("hysteriaSettings", new JSONObject().put("version", 2).put("auth", auth));
            JSONObject mask = null;
            if (salamander) {
                mask = new JSONObject().put("udp", new JSONArray().put(new JSONObject()
                        .put("type", "salamander")
                        .put("settings", new JSONObject().put("password", obfsPassword))));
            }
            if (hop != null) {
                if (mask == null) mask = new JSONObject();
                mask.put("quicParams", new JSONObject().put("udpHop",
                        new JSONObject().put("ports", hop).put("interval", 30)));
            }
            if (mask != null) stream.put("finalmask", mask);
            return new JSONObject()
                    .put("protocol", "hysteria")
                    .put("settings", new JSONObject()
                            .put("version", 2).put("address", host).put("port", port))
                    .put("streamSettings", stream);
        } catch (Exception error) {
            return null;
        }
    }

    /** "443" / "20000-30000" / "443,20000-30000"：每段都在 1..65535，区间左小右大。 */
    private static boolean validPortSpec(String spec) {
        if (spec == null || spec.isEmpty() || spec.length() > 64) return false;
        if (!spec.matches("[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*")) return false;
        for (String part : spec.split(",")) {
            String[] ab = part.split("-");
            int a = Integer.parseInt(ab[0]);
            int b = ab.length > 1 ? Integer.parseInt(ab[1]) : a;
            if (a < 1 || b > 65535 || a > b) return false;
        }
        return true;
    }

    private static boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0 || host.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}");
    }

    // ------------------------------------------------------------ TLS 分片（v3.1）

    /**
     * 能不能对这条出站做 ClientHello 分片：只对 TCP 上的普通 TLS（不含 REALITY / QUIC）。
     * 大陆按 SNI 封锁（workers.dev 等）时，把 ClientHello 拆成几段能让 DPI 认不出域名。
     */
    public static boolean canFragment(JSONObject ob) {
        if (ob == null) return false;
        if ("hysteria".equals(ob.optString("protocol", ""))) return false;
        JSONObject st = ob.optJSONObject("streamSettings");
        if (st == null || !"tls".equals(st.optString("security", ""))) return false;
        String net = lower(st.optString("network", "tcp"));
        return !("kcp".equals(net) || "mkcp".equals(net) || "hysteria".equals(net));
    }

    public static boolean hasFragment(JSONObject ob) {
        JSONObject st = ob == null ? null : ob.optJSONObject("streamSettings");
        JSONObject fm = st == null ? null : st.optJSONObject("finalmask");
        JSONArray tcp = fm == null ? null : fm.optJSONArray("tcp");
        if (tcp == null) return false;
        for (int i = 0; i < tcp.length(); i++) {
            JSONObject m = tcp.optJSONObject(i);
            if (m != null && "fragment".equals(m.optString("type", ""))) return true;
        }
        return false;
    }

    /** 原地加上 ClientHello 分片（finalmask.tcp fragment）。不适用的出站原样返回。 */
    public static JSONObject applyTlsFragment(JSONObject ob) throws Exception {
        if (!canFragment(ob) || hasFragment(ob)) return ob;
        JSONObject st = ob.getJSONObject("streamSettings");
        JSONObject fm = st.optJSONObject("finalmask");
        if (fm == null) {
            fm = new JSONObject();
            st.put("finalmask", fm);
        }
        JSONArray tcp = fm.optJSONArray("tcp");
        if (tcp == null) {
            tcp = new JSONArray();
            fm.put("tcp", tcp);
        }
        tcp.put(new JSONObject().put("type", "fragment").put("settings", new JSONObject()
                .put("packets", "tlshello")
                .put("lengths", new JSONArray().put("100-200"))
                .put("delays", new JSONArray().put("10-20"))));
        return ob;
    }

    /** 拷贝一份再加分片，不改原对象。 */
    public static JSONObject withTlsFragment(JSONObject ob) throws Exception {
        return applyTlsFragment(new JSONObject(ob.toString()));
    }

    private static JSONObject parseSocksHttp(String body, String proto) {
        body = stripFragment(body);
        int qi = body.indexOf('?');
        if (qi >= 0) body = body.substring(0, qi);
        int slash = body.indexOf('/');
        if (slash >= 0) body = body.substring(0, slash);
        String user = "";
        String pass = "";
        int at = body.lastIndexOf('@');
        if (at >= 0) {
            String ui = percentDecode(body.substring(0, at));
            if (ui == null || hasControl(ui)) return null;
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
        if (hp == null || !isAllowedNodeHost(hp[0])) return null;
        try {
            JSONObject server = new JSONObject()
                    .put("address", hp[0]).put("port", Integer.parseInt(hp[1]));
            if (!user.isEmpty()) {
                server.put("users", new JSONArray().put(
                        new JSONObject().put("user", user).put("pass", pass)));
            }
            return new JSONObject()
                    .put("protocol", proto)
                    .put("settings", new JSONObject().put("servers", new JSONArray().put(server)));
        } catch (Exception error) {
            return null;
        }
    }

    /**
     * 由查询参数生成 streamSettings。返回 null 表示这条链接不能用
     * （未知传输、REALITY 参数不合法、明文 VLESS 之外的其它内核拒绝项）。
     */
    private static JSONObject streamSettings(Map<String, String> q) {
        try {
            String net = lower(nonEmpty(qstr(q, "type", "tcp"), "tcp"));
            if ("mkcp".equals(net)) net = "kcp";
            if (!SUPPORTED_NET.contains(net)) return null;
            String sec = lower(nonEmpty(qstr(q, "security", "none"), "none"));
            if (!"none".equals(sec) && !"tls".equals(sec) && !"reality".equals(sec)) return null;

            JSONObject ss = new JSONObject();
            ss.put("network", net);

            if ("reality".equals(sec)) {
                // Xray 26 的 REALITY 只支持 RAW / XHTTP / gRPC。
                if (!("raw".equals(net) || "tcp".equals(net) || "xhttp".equals(net)
                        || "grpc".equals(net))) {
                    return null;
                }
                if ("tcp".equals(net)) {
                    net = "raw";
                    ss.put("network", "raw");
                }
                String pbk = qstr(q, "pbk", "").trim();
                String sid = qstr(q, "sid", "").trim();
                if (!isRealityKey(pbk)) return null;
                if (!sid.isEmpty() && (!sid.matches("[0-9a-fA-F]+")
                        || sid.length() > 16 || (sid.length() & 1) == 1)) {
                    return null;
                }
                String sni = qstr(q, "sni", "");
                if (hasControl(sni)) return null;
                JSONObject r = new JSONObject();
                r.put("serverName", sni);
                r.put("fingerprint", fingerprint(qstr(q, "fp", "")));
                r.put("publicKey", pbk);
                r.put("shortId", sid);
                String spx = qstr(q, "spx", "");
                r.put("spiderX", spx.isEmpty() ? "/" : spx);
                ss.put("security", "reality");
                ss.put("realitySettings", r);
            } else if ("tls".equals(sec)) {
                ss.put("security", "tls");
                JSONObject t = new JSONObject();
                String sni = qstr(q, "sni", "");
                if (sni.isEmpty()) sni = qstr(q, "host", "");
                if (hasControl(sni)) return null;
                if (!sni.isEmpty()) t.put("serverName", sni);
                t.put("fingerprint", fingerprint(qstr(q, "fp", "")));
                String alpn = qstr(q, "alpn", "");
                if (!alpn.isEmpty()) {
                    JSONArray a = new JSONArray();
                    for (String x : alpn.split(",")) {
                        x = x.trim();
                        if (!x.isEmpty() && x.matches("[A-Za-z0-9./_-]+")) a.put(x);
                    }
                    if (a.length() > 0) t.put("alpn", a);
                }
                // 导入节点永远不采用 allowInsecure：中间人可以直接截 TLS。
                t.put("allowInsecure", false);
                ss.put("tlsSettings", t);
            } else {
                ss.put("security", "none");
            }

            if ("ws".equals(net)) {
                String path = nonEmpty(qstr(q, "path", ""), "/");
                String host = qstr(q, "host", "");
                if (hasControl(path) || hasControl(host)) return null;
                JSONObject w = new JSONObject().put("path", path);
                if (!host.isEmpty()) w.put("headers", new JSONObject().put("Host", host));
                ss.put("wsSettings", w);
            } else if ("grpc".equals(net)) {
                String service = qstr(q, "serviceName", "");
                if (service.isEmpty()) service = qstr(q, "path", "");
                if ("/".equals(service)) service = "";
                if (hasControl(service)) return null;
                ss.put("grpcSettings", new JSONObject()
                        .put("serviceName", service)
                        .put("multiMode", "multi".equals(lower(qstr(q, "mode", "gun")))));
            } else if ("httpupgrade".equals(net)) {
                String path = nonEmpty(qstr(q, "path", ""), "/");
                String host = qstr(q, "host", "");
                if (hasControl(path) || hasControl(host)) return null;
                JSONObject h = new JSONObject().put("path", path);
                if (!host.isEmpty()) h.put("host", host);
                ss.put("httpupgradeSettings", h);
            } else if ("xhttp".equals(net)) {
                String path = qstr(q, "path", "");
                String host = qstr(q, "host", "");
                String mode = lower(qstr(q, "mode", ""));
                if (hasControl(path) || hasControl(host)) return null;
                JSONObject x = new JSONObject();
                if (!path.isEmpty()) x.put("path", path);
                if (!host.isEmpty()) x.put("host", host);
                if (XHTTP_MODES.contains(mode)) x.put("mode", mode);
                if (x.length() > 0) ss.put("xhttpSettings", x);
            } else if ("tcp".equals(net)
                    && "http".equals(lower(qstr(q, "headerType", "none")))) {
                ss.put("tcpSettings", new JSONObject().put("header",
                        new JSONObject().put("type", "http")));
            }
            return ss;
        } catch (Exception error) {
            return null;
        }
    }

    // --------------------------------------------------------------- 完整配置

    /** Canonical identity of the complete outbound, excluding its runtime tag. */
    public static String outboundIdentity(JSONObject outbound) throws Exception {
        JSONObject copy = new JSONObject(outbound.toString());
        copy.remove("tag");
        return sha256hex(canonicalJson(copy).toString());
    }

    private static Object canonicalJson(Object value) throws Exception {
        if (value instanceof JSONObject) {
            JSONObject src = (JSONObject) value;
            TreeMap<String, Object> sorted = new TreeMap<>();
            Iterator<String> keys = src.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                sorted.put(key, canonicalJson(src.get(key)));
            }
            return new JSONObject(sorted);
        }
        if (value instanceof JSONArray) {
            JSONArray src = (JSONArray) value;
            JSONArray out = new JSONArray();
            for (int i = 0; i < src.length(); i++) out.put(canonicalJson(src.get(i)));
            return out;
        }
        return JSONObject.NULL.equals(value) ? JSONObject.NULL : value;
    }

    private static String sha256hex(String text) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(UTF8));
        StringBuilder out = new StringBuilder();
        for (byte b : digest) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }

    /**
     * 完整运行配置：TUN 入站 + 全部节点 + 直连 + DNS 出站。
     *
     * @param proxies     已带 {@code proxy-<tag>} 标签的出站
     * @param cgTags      通过 AI 地区闸门的节点基础 tag（不含 proxy- 前缀）
     * @param selectedTag 固定节点基础 tag；"auto"/空 表示 observatory+balancer
     */
    public static String fullConfig(List<JSONObject> proxies, Set<String> cgTags,
                                    String selectedTag) throws Exception {
        return fullConfig(proxies, cgTags, selectedTag, null);
    }

    /**
     * 同上，另带 balancer 的 fallbackTag。
     *
     * <p>v3.0：observatory 刚启动、还没有探测结果时，leastPing 选不出节点，Xray 会落到
     * outbounds 里的第一个出站——以前那是节点池第一个（常常是死节点），表现是「已连接但
     * 什么都打不开」，要等 10 分钟后第一轮探测结束才恢复。现在由调用方传入本机实测最快的
     * 出站作为兜底，冷启动第一秒就走能用的节点。
     *
     * @param fallbackTag 完整出站 tag（如 {@code proxy-i3}）；null/空 表示不设置
     */
    public static String fullConfig(List<JSONObject> proxies, Set<String> cgTags,
                                    String selectedTag, String fallbackTag) throws Exception {
        return fullConfig(proxies, cgTags, selectedTag, fallbackTag, null);
    }

    /**
     * v3.1：再加每个出站的代价系数（完整 tag → 系数 ≥1）。balancer 用 leastLoad，
     * 比较的是「探测延迟（含抖动）× 系数」，系数由 App 侧实测带宽换算——
     * 延迟差不多时优先带宽大的节点，而不是像 leastPing 那样只看握手快不快。
     */
    public static String fullConfig(List<JSONObject> proxies, Set<String> cgTags,
                                    String selectedTag, String fallbackTag,
                                    Map<String, Double> costs) throws Exception {
        if (proxies == null || proxies.isEmpty()) {
            throw new IllegalStateException("没有可用节点");
        }
        boolean hasFallback = fallbackTag != null && !fallbackTag.isEmpty()
                && findByFullTag(proxies, fallbackTag) != null;

        JSONObject cfg = new JSONObject();
        cfg.put("log", new JSONObject().put("loglevel", "warning"));

        // DNS：国内域名走阿里 DNS（直连），其余走 Cloudflare DoH（经代理，防污染）。
        // 敏感域（银行/支付/政务）也必须走国内 DNS，否则查询目标会暴露给节点。
        JSONArray cnDomains = new JSONArray().put("geosite:cn");
        for (String d : RoutingPolicy.SENSITIVE) cnDomains.put("domain:" + d);
        JSONArray servers = new JSONArray();
        servers.put(new JSONObject()
                .put("address", "223.5.5.5")
                .put("domains", cnDomains)
                .put("skipFallback", true));
        servers.put("https://1.1.1.1/dns-query");
        cfg.put("dns", new JSONObject()
                .put("servers", servers)
                .put("queryStrategy", "UseIPv4"));

        // TUN 入站：fd 由 startLoop(config, tunFd) 经环境变量传入。
        JSONObject tun = new JSONObject()
                .put("tag", "tun-in")
                .put("protocol", "tun")
                .put("settings", new JSONObject().put("name", "xray0").put("mtu", 1500))
                .put("sniffing", new JSONObject()
                        .put("enabled", true)
                        // 不嗅探 quic 的话，走 UDP/443 的流量拿不到域名，
                        // 分流规则失效并可能绕过代理。
                        .put("destOverride", new JSONArray()
                                .put("http").put("tls").put("quic")));
        cfg.put("inbounds", new JSONArray().put(tun));

        JSONArray outbounds = new JSONArray();
        for (JSONObject ob : proxies) outbounds.put(ob);
        outbounds.put(new JSONObject()
                .put("tag", "direct")
                .put("protocol", "freedom")
                .put("settings", new JSONObject())
                // freedom.domainStrategy 在 26 已弃用，等价配置迁到 sockopt。
                .put("sockopt", new JSONObject().put("domainStrategy", "UseIPv4")));
        outbounds.put(new JSONObject().put("tag", "dns-out").put("protocol", "dns"));
        // QUIC(udp/443) 与 Private DNS(853/tcp) 一律丢弃：QUIC 会绕过基于域名的
        // 分流，DoT 会让 DNS 查询逃出 VPN 的 dns-out 规则。
        outbounds.put(new JSONObject().put("tag", "block").put("protocol", "blackhole"));
        outbounds.put(new JSONObject().put("tag", "ai-block").put("protocol", "blackhole"));
        cfg.put("outbounds", outbounds);
        cfg.put("stats", new JSONObject());
        cfg.put("policy", new JSONObject().put("system", new JSONObject()
                .put("statsInboundUplink", true)
                .put("statsInboundDownlink", true)
                .put("statsOutboundUplink", true)
                .put("statsOutboundDownlink", true)));

        JSONArray rules = new JSONArray();
        rules.put(rule().put("inboundTag", new JSONArray().put("tun-in"))
                .put("port", 53).put("outboundTag", "dns-out"));
        rules.put(rule().put("network", "udp").put("port", 443)
                .put("outboundTag", "block"));
        rules.put(rule().put("port", 853).put("outboundTag", "block"));
        rules.put(rule().put("ip", new JSONArray().put("geoip:private"))
                .put("outboundTag", "direct"));
        JSONArray sensitive = new JSONArray();
        for (String d : RoutingPolicy.SENSITIVE) sensitive.put("domain:" + d);
        rules.put(rule().put("domain", sensitive).put("outboundTag", "direct"));
        rules.put(rule().put("port", 80).put("outboundTag", "direct"));
        rules.put(rule().put("domain", new JSONArray().put("geosite:cn"))
                .put("outboundTag", "direct"));
        rules.put(rule().put("ip", new JSONArray().put("geoip:cn"))
                .put("outboundTag", "direct"));

        JSONObject routing = new JSONObject().put("domainStrategy", "IPIfNonMatch");
        boolean auto = selectedTag == null || selectedTag.isEmpty()
                || "auto".equals(selectedTag);
        if (!auto && find(proxies, selectedTag) == null) auto = true;

        if (auto) {
            // ChatGPT / Claude 需要地区合格出口：cgTags 里的节点各复制一份到
            // cg-* 前缀，单独组成 cg-balancer。普通流量用全部节点求最快，
            // AI 域名只用合格池，两者都由 observatory 探活。
            int cgCount = 0;
            String cgFallback = null;
            for (JSONObject ob : proxies) {
                String tag = ob.optString("tag", "");
                if (!tag.startsWith("proxy-")) continue;
                String base = tag.substring(6);
                if (cgTags == null || !cgTags.contains(base)) continue;
                JSONObject copy = new JSONObject(ob.toString());
                copy.put("tag", "cg-" + base);
                outbounds.put(copy);
                if (cgFallback == null) cgFallback = "cg-" + base;
                cgCount++;
            }
            JSONArray subjects = new JSONArray().put("proxy-");
            JSONObject mainBalancer = new JSONObject()
                    .put("tag", "balancer")
                    .put("selector", new JSONArray().put("proxy-"))
                    .put("strategy", leastLoad(costs, false));
            if (hasFallback) mainBalancer.put("fallbackTag", fallbackTag);
            JSONArray balancers = new JSONArray().put(mainBalancer);
            if (cgCount > 0) {
                subjects.put("cg-");
                JSONObject cgBalancer = new JSONObject()
                        .put("tag", "cg-balancer")
                        .put("selector", new JSONArray().put("cg-"))
                        .put("strategy", leastLoad(costs, true));
                if (cgFallback != null) cgBalancer.put("fallbackTag", cgFallback);
                balancers.put(cgBalancer);
            }
            // v3.1：observatory+leastPing → burstObservatory+leastLoad。
            // burst 每个节点保留最近 3 次探测，leastLoad 比较「平均延迟+抖动」再乘代价系数，
            // 一次偶发超时不会把稳定节点踢掉，忽快忽慢的节点也不会被选中；expected=1 保证
            // 出口固定（不随机换 IP，ChatGPT 等站不会因为出口跳动而风控）。
            // 3 分钟一轮 204 探测，≤30 个出口约 2~3 MB/小时。
            cfg.put("burstObservatory", new JSONObject()
                    .put("subjectSelector", subjects)
                    .put("pingConfig", new JSONObject()
                            .put("destination", "https://www.gstatic.com/generate_204")
                            .put("interval", "3m")
                            .put("sampling", 3)
                            .put("timeout", "6s")));
            routing.put("balancers", balancers);
            JSONArray aiDomains = new JSONArray();
            for (String d : RoutingPolicy.AI_DOMAINS) aiDomains.put("domain:" + d);
            if (cgCount > 0) {
                rules.put(rule().put("network", "tcp,udp")
                        .put("domain", aiDomains)
                        .put("balancerTag", "cg-balancer"));
            } else {
                rules.put(rule().put("network", "tcp,udp")
                        .put("domain", aiDomains)
                        .put("outboundTag", "ai-block"));
            }
            rules.put(rule().put("network", "tcp,udp").put("balancerTag", "balancer"));
        } else {
            JSONArray aiDomains = new JSONArray();
            for (String d : RoutingPolicy.AI_DOMAINS) aiDomains.put("domain:" + d);
            boolean selectedIsAi = cgTags != null && cgTags.contains(selectedTag);
            rules.put(rule().put("network", "tcp,udp")
                    .put("domain", aiDomains)
                    .put("outboundTag", selectedIsAi ? "proxy-" + selectedTag : "ai-block"));
            rules.put(rule().put("network", "tcp,udp")
                    .put("outboundTag", "proxy-" + selectedTag));
        }
        routing.put("rules", rules);
        cfg.put("routing", routing);
        return cfg.toString();
    }

    /**
     * leastLoad：expected=1（只挑一个，出口稳定）、maxRTT 5s、最近 3 次里失败超过 1 次就不选。
     * costs 用锚定正则（^tag$）：非正则匹配是子串包含，proxy-i1 会误伤 proxy-i10~i19。
     */
    private static JSONObject leastLoad(Map<String, Double> costs, boolean cgCopy) throws Exception {
        JSONObject settings = new JSONObject()
                .put("expected", 1)
                .put("maxRTT", "5s")
                .put("tolerance", 0.34);
        if (costs != null && !costs.isEmpty()) {
            JSONArray arr = new JSONArray();
            List<String> tags = new ArrayList<>(costs.keySet());
            java.util.Collections.sort(tags);
            for (String tag : tags) {
                Double v = costs.get(tag);
                if (v == null || v.isNaN() || v <= 0) continue;
                if (!tag.matches("proxy-[A-Za-z0-9_-]{1,32}")) continue;
                String t = cgCopy ? "cg-" + tag.substring(6) : tag;
                double rounded = Math.round(Math.min(20.0, Math.max(1.0, v)) * 100.0) / 100.0;
                arr.put(new JSONObject().put("regexp", true)
                        .put("match", "^" + t + "$").put("value", rounded));
            }
            if (arr.length() > 0) settings.put("costs", arr);
        }
        return new JSONObject().put("type", "leastLoad").put("settings", settings);
    }

    private static JSONObject rule() {
        return new JSONObject();
    }

    private static JSONObject find(List<JSONObject> proxies, String baseTag) {
        for (JSONObject ob : proxies) {
            if (("proxy-" + baseTag).equals(ob.optString("tag", ""))) return ob;
        }
        return null;
    }

    private static JSONObject findByFullTag(List<JSONObject> proxies, String fullTag) {
        for (JSONObject ob : proxies) {
            if (fullTag.equals(ob.optString("tag", ""))) return ob;
        }
        return null;
    }

    /** 单节点最小配置，供 Libv2ray.measureOutboundDelay 做 Dry-Run 或测速。 */
    public static String measureConfigOf(JSONObject outbound) throws Exception {
        JSONObject cfg = new JSONObject();
        cfg.put("log", new JSONObject().put("loglevel", "warning"));
        cfg.put("outbounds", new JSONArray().put(outbound));
        cfg.put("routing", new JSONObject()
                .put("domainStrategy", "IPIfNonMatch")
                .put("rules", new JSONArray()));
        return cfg.toString();
    }

    // ------------------------------------------------------------- 校验小工具

    private static boolean validSs2022Key(String password, int want) {
        if (password == null || password.isEmpty()) return false;
        for (String part : password.split(":", -1)) {
            String key = part.trim();
            if (key.isEmpty()) return false;
            byte[] raw = b64Decode(key);
            if (raw == null || raw.length != want) return false;
        }
        return true;
    }

    /** REALITY publicKey 是 32 字节的 base64url（43 字符左右，可带 padding）。 */
    private static boolean isRealityKey(String text) {
        if (text == null || text.isEmpty()) return false;
        byte[] raw = b64Decode(text);
        return raw != null && raw.length == 32;
    }

    private static String fingerprint(String raw) {
        String fp = lower(raw == null ? "" : raw.trim());
        return UTLS_FINGERPRINTS.contains(fp) ? fp : "chrome";
    }

    /** 宽松 base64（标准/URL-safe、缺 padding、带换行都认）。失败返回 null。 */
    public static byte[] b64Decode(String text) {
        if (text == null) return null;
        StringBuilder sb = new StringBuilder(text.length());
        boolean padded = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
            if (c == '=') {
                padded = true;
                continue;
            }
            if (padded) return null; // padding 后面不能再有数据
            if (c == '-') c = '+';
            else if (c == '_') c = '/';
            if (base64Value(c) < 0) return null;
            sb.append(c);
        }
        int len = sb.length();
        if (len == 0 || len % 4 == 1) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(len * 3 / 4 + 3);
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < len; i++) {
            buffer = (buffer << 6) | base64Value(sb.charAt(i));
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((buffer >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    private static int base64Value(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    /** 宽松 base64 解码成 UTF-8 文本。失败返回 null。 */
    public static String tryB64(String s) {
        if (s == null) return null;
        byte[] raw = b64Decode(s.trim());
        if (raw == null) return null;
        String out = new String(raw, UTF8);
        return out.isEmpty() ? null : out;
    }

    /** 百分号解码；'+' 保持原样（订阅链接里的密码可能就是 '+'）。 */
    public static String percentDecode(String text) {
        if (text == null) return null;
        try {
            StringBuilder plain = new StringBuilder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c != '%') {
                    plain.append(c);
                    continue;
                }
                if (plain.length() > 0) {
                    out.write(plain.toString().getBytes(UTF8));
                    plain.setLength(0);
                }
                if (i + 2 >= text.length()) return null;
                int hi = hexValue(text.charAt(i + 1));
                int lo = hexValue(text.charAt(i + 2));
                if (hi < 0 || lo < 0) return null;
                out.write((hi << 4) | lo);
                i += 2;
            }
            if (plain.length() > 0) out.write(plain.toString().getBytes(UTF8));
            return new String(out.toByteArray(), UTF8);
        } catch (Exception error) {
            return null;
        }
    }

    private static int hexValue(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> m = new HashMap<>();
        if (query == null || query.isEmpty()) return m;
        for (String kv : query.split("&")) {
            if (kv.isEmpty()) continue;
            int i = kv.indexOf('=');
            String k = i < 0 ? kv : kv.substring(0, i);
            String v = i < 0 ? "" : kv.substring(i + 1);
            String dk = percentDecode(k);
            String dv = percentDecode(v);
            if (dk == null || dv == null) return null;
            if (dk.length() > 64 || dv.length() > 2048) return null;
            if (hasControl(dk) || hasControl(dv)) return null;
            m.put(dk, dv);
        }
        return m;
    }

    private static boolean hasControl(String s) {
        if (s == null) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) return true;
        }
        return false;
    }

    private static String[] splitHostPort(String hp) {
        hp = hp == null ? "" : hp.trim();
        // 不少分享链接把 authority 写成 host:port/（路径并非传输参数，WS 的
        // path 在 query 里）。以前整条链接因此被丢弃，节点显示“不可用”。
        int slash = hp.indexOf('/');
        if (slash >= 0) hp = hp.substring(0, slash);
        if (hp.isEmpty()) return null;
        try {
            if (hp.startsWith("[")) {
                int e = hp.indexOf(']');
                if (e < 0) return null;
                String host = hp.substring(1, e);
                String rest = hp.substring(e + 1).trim();
                int port = 443;
                if (!rest.isEmpty()) {
                    if (!rest.startsWith(":")) return null;
                    port = Integer.parseInt(rest.substring(1));
                }
                if (host.isEmpty() || port < 1 || port > 65535) return null;
                return new String[]{host, String.valueOf(port)};
            }
            int c = hp.lastIndexOf(':');
            if (c < 0) return new String[]{hp, "443"};
            if (c == 0) return null;
            if (hp.indexOf(':') != c) return null; // 裸 IPv6 必须带方括号
            String host = hp.substring(0, c);
            int port = Integer.parseInt(hp.substring(c + 1));
            if (host.isEmpty() || port < 1 || port > 65535) return null;
            return new String[]{host, String.valueOf(port)};
        } catch (Exception error) {
            return null;
        }
    }

    /**
     * Xray 的 UUID 规则（实测）：≤30 字符的任意字符串会映射成 UUIDv5；32 位纯 hex
     * 直接当 UUID；36 位必须是标准带连字符 UUID；其它长度（31~35、>36）整份配置报错。
     */
    private static boolean validUserId(String id) {
        if (id == null || id.isEmpty() || hasControl(id)) return false;
        int n = id.length();
        if (n <= 30) return true;
        if (n == 32) return id.matches("[0-9a-fA-F]{32}");
        if (n == 36) {
            return id.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                    + "-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
        }
        return false;
    }

    private static boolean isAllowedNodeHost(String host) {
        String h = host == null ? "" : host.trim();
        if (h.isEmpty()) return false;
        try {
            SubscriptionGuard.checkHost(h);
            return true;
        } catch (SubscriptionGuard.Rejected rejected) {
            return false;
        } catch (Throwable ignored) {
            return true;
        }
    }

    private static String stripFragment(String s) {
        int h = s.indexOf('#');
        return h >= 0 ? s.substring(0, h) : s;
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
                } else if (st.has("address")) {
                    host = st.optString("address", "?"); // hysteria：地址直接在 settings 里
                }
            }
            return proto + " " + host;
        } catch (Exception error) {
            return "?";
        }
    }

    public static String describe(JSONObject ob) {
        return displayName(ob);
    }

    private static String str(JSONObject o, String key) {
        Object v = o.opt(key);
        if (v == null || v == JSONObject.NULL) return "";
        String s = String.valueOf(v).trim();
        return "null".equalsIgnoreCase(s) ? "" : s;
    }

    private static int intValue(Object v, int fallback) {
        if (v == null || v == JSONObject.NULL) return fallback;
        if (v instanceof Number) return ((Number) v).intValue();
        try {
            return Integer.parseInt(String.valueOf(v).trim());
        } catch (Exception error) {
            return fallback;
        }
    }

    private static String nonEmpty(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static String qstr(Map<String, String> q, String key, String fallback) {
        String v = q.get(key);
        return v == null ? fallback : v;
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}