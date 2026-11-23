import com.luhui.phoneproxy.NodeConfigCodec;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 投毒语料：200+ 条畸形/恶意分享链接。
 *
 * <p>断言两件事：
 * 1. parseUri 对任何输入都不抛异常（返回 null 或出站）；
 * 2. 所有被接受的出站能拼成完整配置，交给真实 Xray 做 {@code run -test}
 *    （由 phone/tools/check_poison.py 执行）。
 *
 * <p>这个文件只跑在普通 JDK 上，不打进 APK；可以用 java.util.Base64。
 */
public final class PoisonHarness {

    private static final String UUID = "11111111-1111-1111-1111-111111111111";
    /** 43 字符 base64url，解码为 32 字节；Xray 接受。 */
    private static final String PBK = "YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String SS2022_16 = "AAAAAAAAAAAAAAAAAAAAAA==";
    private static final String SS2022_32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private static final List<String[]> CASES = new ArrayList<>();

    private PoisonHarness() {
    }

    public static void main(String[] args) throws Exception {
        buildCases();
        JSONArray accepted = new JSONArray();
        List<JSONObject> proxies = new ArrayList<>();
        Set<String> cgTags = new HashSet<>();
        int rejected = 0;
        int parseCrashes = 0;

        for (int i = 0; i < CASES.size(); i++) {
            String name = CASES.get(i)[0];
            String uri = CASES.get(i)[1];
            JSONObject ob = null;
            try {
                ob = NodeConfigCodec.parseUri(uri);
            } catch (Throwable t) {
                parseCrashes++;
                System.err.println("PARSE CRASH " + name + ": " + t);
            }
            if (ob == null) {
                rejected++;
                continue;
            }
            ob.put("tag", "proxy-p" + i);
            proxies.add(ob);
            JSONObject item = new JSONObject();
            item.put("case", name);
            item.put("protocol", ob.optString("protocol", ""));
            item.put("outbound", ob);
            accepted.put(item);
            if (i % 23 == 0 && cgTags.size() < 3) cgTags.add("p" + i);
        }

        JSONObject out = new JSONObject();
        out.put("total", CASES.size());
        out.put("accepted", accepted.length());
        out.put("rejected", rejected);
        out.put("parse_crashes", parseCrashes);
        out.put("accepted_nodes", accepted);
        if (proxies.isEmpty()) {
            out.put("full_auto", JSONObject.NULL);
            out.put("full_manual", JSONObject.NULL);
        } else {
            out.put("full_auto", new JSONObject(
                    NodeConfigCodec.fullConfig(proxies, cgTags, "auto")));
            String firstTag = proxies.get(0).optString("tag", "").substring(6);
            out.put("full_manual", new JSONObject(
                    NodeConfigCodec.fullConfig(proxies, cgTags, firstTag)));
        }

        if (args.length > 0) {
            try (Writer w = new OutputStreamWriter(
                    new FileOutputStream(args[0]), Charset.forName("UTF-8"))) {
                w.write(out.toString());
            }
        }
        System.out.println("cases=" + CASES.size()
                + " accepted=" + accepted.length()
                + " rejected=" + rejected
                + " parse_crashes=" + parseCrashes);
        if (parseCrashes > 0) System.exit(3);

        // 定向回归：authority 后面跟路径（host:port/）不该整条被丢弃。分享站常这么写，
        // 以前会判成"不可用"，而它并不是畸形链接。放在语料之外，避免打乱 golden 的 tag 序列。
        String slashUri = "vless://" + UUID + "@1.2.3.4:443/?encryption=none"
                + "&security=reality&sni=www.example.com&fp=chrome&pbk=" + PBK + "&sid=&type=raw#ok";
        if (NodeConfigCodec.parseUri(slashUri) == null) {
            System.err.println("REGRESSION: host:port/ 被拒绝");
            System.exit(4);
        }
    }

    // ---------------------------------------------------------------- 语料

    private static void buildCases() {
        // 合法基线：每个协议/传输至少一条，确保 accepted 不为 0。
        add("vless-reality-raw", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=reality&sni=www.example.com&fp=chrome&pbk=" + PBK
                + "&sid=&type=raw#ok");
        add("vless-reality-grpc", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=reality&sni=www.example.com&fp=firefox&pbk=" + PBK
                + "&sid=ab12&type=grpc&serviceName=svc#ok");
        add("vless-reality-xhttp", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=reality&sni=www.example.com&pbk=" + PBK
                + "&type=xhttp&path=%2Fx&mode=auto#ok");
        add("vless-tls-ws", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=tls&sni=a.example.com&fp=safari&type=ws&host=a.example.com"
                + "&path=%2Fws%3Fed%3D2048#ok");
        add("vless-tls-grpc", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=tls&sni=a.example.com&type=grpc&serviceName=svc&mode=multi#ok");
        add("vless-tls-tcp-http", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=tls&sni=a.example.com&type=tcp&headerType=http#ok");
        add("vless-tls-httpupgrade", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=tls&sni=a.example.com&type=httpupgrade&host=h.example.com&path=%2Fu#ok");
        add("vless-tls-ipv6", "vless://" + UUID + "@[2001:db8::1]:443?encryption=none"
                + "&security=tls&sni=a.example.com&type=ws&path=%2F#ok");
        add("vless-vision", "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                + "&security=tls&sni=a.example.com&flow=xtls-rprx-vision&type=tcp#ok");

        add("vmess-ws-tls", "vmess://" + b64(vmessJson("1.2.3.4", "443", "ws", "tls", "a.example.com")));
        add("vmess-tcp-none", "vmess://" + b64(vmessJson("1.2.3.4", 443, "tcp", "none", "")));
        add("vmess-grpc-tls", "vmess://" + b64(vmessJson("1.2.3.4", "443", "grpc", "tls", "a.example.com")));

        add("trojan-tls", "trojan://p%40ss@1.2.3.4:443?security=tls&sni=a.example.com#ok");
        add("trojan-reality", "trojan://pass@1.2.3.4:443?security=reality&sni=a.example.com"
                + "&pbk=" + PBK + "&type=raw#ok");
        add("trojan-none", "trojan://pass@1.2.3.4:443?security=none#ok");

        add("ss-aead", "ss://" + b64("aes-128-gcm:password") + "@1.2.3.4:8388#ok");
        add("ss-2022-16", "ss://" + b64("2022-blake3-aes-128-gcm:" + SS2022_16) + "@1.2.3.4:8388#ok");
        add("ss-2022-32", "ss://" + b64("2022-blake3-chacha20-poly1305:" + SS2022_32) + "@1.2.3.4:8388#ok");
        add("ss-sip002-plain", "ss://chacha20-poly1305:p%40ss@1.2.3.4:8388#ok");

        add("socks-auth", "socks://u%40ser:p%3Ass@1.2.3.4:1080#ok");
        add("socks5-plain", "socks5://1.2.3.4:1080#ok");
        add("http-proxy", "http://user:pass@1.2.3.4:8080#ok");

        // ---- 协议/传输/加密层面的旧规则与内核已移除项 ----
        String vbase = "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&type=";
        for (String net : new String[]{"quic", "h2", "http", "unknown", "ws ", "WSS", "tcp,ws", ""}) {
            add("net-" + net.trim().replace(",", "-"), vbase + url(net) + "#x");
        }
        for (String sec : new String[]{"none", "", "xtls", "tls1.3", "REALITY", "reality "}) {
            add("security-" + sec.trim(), "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                    + "&security=" + url(sec) + "&sni=a.example.com&pbk=" + PBK
                    + "&sid=ab&type=raw#x");
        }
        for (String enc : new String[]{"mlkem768x25519plus.native.600s", "aes-128-gcm", "none "}) {
            add("encryption-" + enc.split("\\.")[0], "vless://" + UUID + "@1.2.3.4:443?encryption="
                    + url(enc) + "&security=tls&sni=a.example.com&type=tcp#x");
        }
        for (String flow : new String[]{"weird", "xtls-rprx-direct", "xtls-rprx-vision "}) {
            add("flow-" + flow.trim(), "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                    + "&security=tls&sni=a.example.com&flow=" + url(flow) + "&type=tcp#x");
        }
        for (String pbk : new String[]{"", "short", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                PBK.substring(0, 40)}) {
            add("reality-pbk-" + Math.abs(pbk.hashCode() % 1000), "vless://" + UUID
                    + "@1.2.3.4:443?encryption=none&security=reality&sni=a.example.com"
                    + "&pbk=" + url(pbk) + "&sid=ab&type=raw#x");
        }
        for (String sid : new String[]{"a", "abc", "zz", "00112233445566778", "0011223344556677"}) {
            add("reality-sid-" + sid.length() + "-" + sid.substring(0, 1), "vless://" + UUID
                    + "@1.2.3.4:443?encryption=none&security=reality&sni=a.example.com"
                    + "&pbk=" + PBK + "&sid=" + url(sid) + "&type=raw#x");
        }
        for (String fp : new String[]{"", "nonsense-fp", "CHROME", "chrome_psk"}) {
            add("fp-" + fp, "vless://" + UUID + "@1.2.3.4:443?encryption=none"
                    + "&security=tls&sni=a.example.com&fp=" + url(fp) + "&type=tcp#x");
        }

        // ---- 地址与端口 ----
        String[] hosts = {
                "127.0.0.1", "localhost", "foo.localhost", "printer.local",
                "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
                "169.254.169.254", "0.0.0.0", "100.64.0.1", "224.0.0.1",
                "2130706433", "0x7f000001", "0177.0.0.1", "127.1",
                "metadata.google.internal", "metadata",
                "[::1]", "[::]", "[fe80::1]", "[fc00::1]", "[fd00::1]", "[::ffff:127.0.0.1]",
                "1.2.3.4", "example.com", "EXAMPLE.com", "example.com.", "exa_mple.com",
                "a..b", "-a.com", "a-.com", "例子.cn",
        };
        for (int i = 0; i < hosts.length; i++) {
            add("host-" + i, "vless://" + UUID + "@" + hosts[i] + ":443?encryption=none"
                    + "&security=tls&sni=a.example.com&type=tcp#x");
        }
        String[] ports = {"0", "-1", "65536", "99999", "abc", "", "1", "65535", "443"};
        for (String port : ports) {
            add("port-" + port, "vless://" + UUID + "@1.2.3.4:" + port
                    + "?encryption=none&security=tls&sni=a.example.com&type=tcp#x");
        }

        // ---- 控制字符 / 编码 / 超长 ----
        add("crlf-fragment", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com#ok\r\nHost: evil");
        add("crlf-query-encoded", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&path=%2F%0d%0aX&type=ws#x");
        add("nul-query", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&path=%00&type=ws#x");
        add("bad-percent", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&path=%zz&type=ws#x");
        add("trailing-percent", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&path=%&type=ws#x");
        add("backslash", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&path=\\x&type=ws#x");
        add("long-path", "vless://" + UUID + "@1.2.3.4:443?encryption=none&security=tls"
                + "&sni=a.example.com&path=%2F" + repeat("a", 3000) + "&type=ws#x");
        add("long-uri", "vless://" + UUID + "@1.2.3.4:443?" + repeat("a=1&", 3000) + "#x");
        add("empty", "");
        add("spaces", "   ");
        add("no-scheme", UUID + "@1.2.3.4:443");
        add("file", "file:///etc/passwd");
        add("ftp", "ftp://1.2.3.4:21#x");
        add("https-share", "https://1.2.3.4:443#x");
        add("vless-single-slash", "vless:/" + UUID + "@1.2.3.4:443#x");
        add("vless-no-user", "vless://@1.2.3.4:443?security=tls#x");
        add("vless-empty-user", "vless://" + "@1.2.3.4:443?security=tls#x");
        add("vless-no-host", "vless://" + UUID + "@:443?security=tls#x");
        add("vless-no-port", "vless://" + UUID + "@1.2.3.4?security=tls#x");
        add("vless-userinfo", "vless://u:p@" + UUID + "@1.2.3.4:443?security=tls#x");
        add("uppercase-scheme", "VLESS://" + UUID + "@1.2.3.4:443?security=tls&sni=a.example.com#x");

        // ---- vmess 畸形 ----
        add("vmess-broken-b64", "vmess://!!!!");
        add("vmess-not-json", "vmess://" + b64("hello world"));
        add("vmess-empty-object", "vmess://" + b64("{}"));
        add("vmess-no-add", "vmess://" + b64("{\"id\":\"" + UUID + "\",\"port\":443}"));
        add("vmess-no-id", "vmess://" + b64("{\"add\":\"1.2.3.4\",\"port\":443}"));
        add("vmess-null-fields", "vmess://" + b64("{\"add\":null,\"port\":null,"
                + "\"id\":null,\"net\":null,\"tls\":null}"));
        add("vmess-string-null", "vmess://" + b64("{\"add\":\"1.2.3.4\",\"port\":\"443\","
                + "\"id\":\"" + UUID + "\",\"net\":\"null\",\"tls\":\"null\"}"));
        add("vmess-private", "vmess://" + b64(vmessJson("192.168.0.10", 443, "ws", "tls", "a.com")));
        add("vmess-loopback", "vmess://" + b64(vmessJson("127.0.0.1", 443, "tcp", "none", "")));
        add("vmess-bad-port", "vmess://" + b64(vmessJson("1.2.3.4", 65536, "tcp", "none", "")));
        add("vmess-quic", "vmess://" + b64(vmessJson("1.2.3.4", 443, "quic", "tls", "a.com")));
        add("vmess-h2", "vmess://" + b64(vmessJson("1.2.3.4", 443, "h2", "tls", "a.com")));
        add("vmess-upper-tls", "vmess://" + b64(vmessJson("1.2.3.4", 443, "ws", "TLS", "a.com")));

        // ---- ss 畸形 ----
        add("ss-bad-b64", "ss://" + "@1.2.3.4:8388#x");
        add("ss-no-password", "ss://" + b64("aes-128-gcm:") + "@1.2.3.4:8388#x");
        add("ss-legacy-chacha20", "ss://" + b64("chacha20:pass") + "@1.2.3.4:8388#x");
        add("ss-legacy-cfb", "ss://" + b64("aes-256-cfb:pass") + "@1.2.3.4:8388#x");
        add("ss-plain", "ss://" + b64("plain:pass") + "@1.2.3.4:8388#x");
        add("ss-bad-2022-key", "ss://" + b64("2022-blake3-aes-128-gcm:short") + "@1.2.3.4:8388#x");
        add("ss-plugin", "ss://" + b64("aes-128-gcm:pass") + "@1.2.3.4:8388/?plugin=v2ray-plugin#x");
        add("ss-private", "ss://" + b64("aes-128-gcm:pass") + "@10.1.2.3:8388#x");
        add("ss-port0", "ss://" + b64("aes-128-gcm:pass") + "@1.2.3.4:0#x");
        add("ss-no-host", "ss://" + b64("aes-128-gcm:pass") + "#x");
        add("ss-frag-only", "ss://#x");

        // ---- trojan / socks / http 畸形 ----
        add("trojan-empty-pass", "trojan://@1.2.3.4:443?security=tls#x");
        add("trojan-private", "trojan://pass@10.0.0.9:443?security=tls#x");
        add("trojan-bad-sec", "trojan://pass@1.2.3.4:443?security=xtls#x");
        add("trojan-reality-no-pbk", "trojan://pass@1.2.3.4:443?security=reality&sni=a.com#x");
        add("trojan-port0", "trojan://pass@1.2.3.4:0?security=tls#x");
        add("socks-private", "socks://u:p@192.168.1.1:1080#x");
        add("socks-port", "socks://1.2.3.4:70000#x");
        add("http-private", "http://user:pass@127.0.0.1:8080#x");
        add("http-no-port", "http://user:pass@1.2.3.4#x");

        // ---- 批量变异：每条合法链接随机字段替换 ----
        String[] queries = {
                "", "security=tls", "security=none", "security=reality",
                "security=tls&type=quic", "security=tls&type=h2",
                "security=tls&type=ws&path=%2Fx", "security=tls&type=grpc&serviceName=s",
                "security=tls&type=xhttp", "security=tls&type=kcp",
                "security=tls&type=httpupgrade", "security=tls&type=mkcp",
                "encryption=none&security=tls&sni=a.com",
                "encryption=mlkem768x25519plus.native.600s&security=tls",
                "security=tls&fp=golang", "security=tls&fp=randomized",
                "security=tls&alpn=h2,http%2F1.1", "security=tls&alpn=%00",
                "security=reality&pbk=" + PBK + "&sid=&sni=a.com&type=raw",
                "security=reality&pbk=" + PBK + "&sid=AB&sni=a.com&type=grpc",
                "security=reality&pbk=" + PBK + "&sid=zz&type=raw",
                "security=reality&pbk=" + PBK + "&sid=00112233445566778&type=raw",
                "security=reality&pbk=&sid=&type=raw",
                "security=reality&pbk=" + PBK + "&sid=&type=ws",
                "flow=xtls-rprx-vision&security=tls",
                "flow=bad&security=tls",
        };
        String[] schemes = {"vless", "trojan"};
        for (String scheme : schemes) {
            for (int q = 0; q < queries.length; q++) {
                String user = "trojan".equals(scheme) ? "pass" : UUID;
                add(scheme + "-mut-" + q, scheme + "://" + user + "@1.2.3.4:443?"
                        + queries[q] + "#x");
            }
        }
        for (int i = 0; i < 60; i++) {
            String uri = "vless://" + UUID + "@1.2.3.4:" + (440 + i) + "?"
                    + queries[i % queries.length]
                    + "&extra=" + Integer.toHexString(i) + "#x";
            add("vless-bulk-" + i, uri);
        }
        for (int i = 0; i < 40; i++) {
            add("vmess-bulk-" + i, "vmess://" + b64(vmessJson("1.2.3.4", 443,
                    i % 2 == 0 ? "ws" : "tcp", i % 3 == 0 ? "tls" : "none", "a.com")));
        }
        for (int i = 0; i < 30; i++) {
            add("random-" + i, randomUri(i));
        }
    }

    private static void add(String name, String uri) {
        CASES.add(new String[]{name, uri});
    }

    private static String vmessJson(Object host, Object port, String net, String tls, String sni) {
        JSONObject v = new JSONObject();
        v.put("v", "2");
        v.put("ps", "test");
        v.put("add", host);
        v.put("port", port);
        v.put("id", UUID);
        v.put("aid", "0");
        v.put("scy", "auto");
        v.put("net", net);
        v.put("type", "none");
        v.put("host", sni);
        v.put("path", "/ws");
        v.put("tls", tls);
        v.put("sni", sni);
        v.put("fp", "chrome");
        return v.toString();
    }

    private static String b64(String s) {
        return java.util.Base64.getEncoder().encodeToString(s.getBytes(Charset.forName("UTF-8")));
    }

    private static String url(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return "";
        }
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    private static String randomUri(int seed) {
        String[] pieces = {
                "vless://", "vmess://", "ss://", "trojan://", "socks://", "http://",
                "file://", "https://", "", "@", "::", "@@", "?&=&",
                UUID, "127.0.0.1", "1.2.3.4", PBK, "%00", "%zz", "\r\n", " ",
                "/x", "#frag", ":443", ":0", ":99999", "type=quic", "security=reality",
        };
        StringBuilder sb = new StringBuilder();
        int x = seed * 1103515245 + 12345;
        for (int i = 0; i < 8; i++) {
            x = x * 1103515245 + 12345;
            sb.append(pieces[Math.abs(x) % pieces.length]);
        }
        return sb.toString();
    }
}