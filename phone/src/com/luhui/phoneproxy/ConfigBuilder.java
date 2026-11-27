package com.luhui.phoneproxy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import libv2ray.Libv2ray;

/**
 * v2：内置节点（随 APK 打包）+ 用户导入节点（剪贴板 / 订阅链接）合并成一份 Xray 配置。
 *
 * 自动模式使用 Xray observatory + balancer(leastPing)：
 *   - 启动无需先测速，秒连；
 *   - 每 600s（10 分钟）并发探测全部节点，坏节点自动跳过，新连接自动选最快可用节点；
 *   - 节点随时失效也不用手动切。
 * 手动模式把默认路由固定到所选节点。
 */
public final class ConfigBuilder {

    public static final String PREFS = "imported";
    public static final String KEY_URIS = "uris";
    /**
     * 导入池上限。v3.0 起导入池只放「本机实测能连上」的节点（死节点会被
     * {@link NodePool#pruneDeadImports} 清掉），80 个足够；运行配置再从里面挑最快的 30 个。
     */
    public static final int MAX_IMPORTED = 80;
    /** 单个源最多取多少条候选，避免一个巨型聚合列表挤掉其它源。 */
    private static final int PER_SOURCE = 80;
    /** 一次补充最多实测多少个候选（去重后）。TCP 预筛 32 并发，约 1 分钟。 */
    private static final int CANDIDATE_MAX = 480;

    /**
     * 公开订阅源：仓库里只放 URL，**不含任何节点凭据**，运行时才去抓。
     * 每行 = {名字, GitHub raw 地址}；jsDelivr 与 ghfast.top 镜像由 {@link #mirrorsOf} 自动生成
     * （大陆直连 raw.githubusercontent.com 常被 DNS 污染）。全部失败就跳过这一条。
     * 这些是第三方公开聚合列表，节点质量与存活率不受本项目控制。
     *
     * <p>v3.0 顺序：面向大陆用户、自称在国内测过速的源放前面，伊朗/俄罗斯向的大聚合放后面。
     * 顺序只影响去重时谁先占位——是否入池完全由本机实测决定，所以列表写宽一点没有坏处，
     * 抓不到（404/被墙）的源只是在日志里显示失败。
     *
     * <p>v3.2（2026-11-23 下午）：每条路径都在用户的大陆网络下实际拉取验证过（状态 200、内容非空）。
     * 去掉了 404 的 aiboboxx/v2、mfuu 和与 peasoft 内容完全相同的 chengaopan；新增
     * tony163（自称湖北移动测速后上传）、Barabama clashmeta.txt（约 1800 条，其中 166 条 hysteria2）、
     * free18。这张表只是兜底：运行时会先读仓库里的 {@code phone/sources.json}（见 {@link #REMOTE_SOURCES}），
     * 源失效时改仓库即可，不用重新发 APK。
     */
    public static final String[][] PUBLIC_SOURCES = {
            {"peasoft", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt"},
            {"ermaozi", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"},
            {"tony163", "https://raw.githubusercontent.com/tony163/node_free/main/v2ray.txt"},
            {"Barabama", "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.txt"},
            {"free18", "https://raw.githubusercontent.com/free18/v2ray/main/v.txt"},
            {"aiboboxx-sub", "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/sub"},
            {"Pawdroid", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"},
            {"ripaojiedian", "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub"},
            {"freefq", "https://raw.githubusercontent.com/freefq/free/master/v2"},
            {"barry-far", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt"},
            {"mahdibland", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"},
            {"ALIILAPRO", "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt"},
    };

    /**
     * v3.2：仓库里的源清单（JSON 数组 {@code [{"name":..,"url":..}]}），jsDelivr / ghfast / raw 三路取，
     * 4~8 秒超时；拿到 ≥3 条合法条目才替换内置表。只接受 https 的 GitHub raw / jsDelivr / gist 地址，
     * 防止清单被篡改成指向内网或任意主机（抓取本身还要再过 SubscriptionGuard）。
     */
    static final String[] REMOTE_SOURCES = {
            "https://cdn.jsdelivr.net/gh/gedouluhui/pc-phone-proxy@main/phone/sources.json",
            "https://ghfast.top/https://raw.githubusercontent.com/gedouluhui/pc-phone-proxy/main/phone/sources.json",
            "https://raw.githubusercontent.com/gedouluhui/pc-phone-proxy/main/phone/sources.json",
    };

    /** 远程清单 → 源表；失败返回内置 {@link #PUBLIC_SOURCES}。log 里写明用了哪份。 */
    static String[][] resolveSources(List<String> log) {
        for (String u : REMOTE_SOURCES) {
            try {
                List<String[]> got = new ArrayList<>();
                JSONArray arr = new JSONArray(fetchText(u, 8000));
                for (int i = 0; i < arr.length() && got.size() < 40; i++) {
                    JSONObject o = arr.optJSONObject(i);
                    if (o == null) continue;
                    String name = o.optString("name", "").trim();
                    String url = o.optString("url", "").trim();
                    if (name.isEmpty() || name.length() > 40 || !allowedSourceUrl(url)) continue;
                    got.add(new String[]{name, url});
                }
                if (got.size() >= 3) {
                    log.add("源清单：使用仓库最新版（" + got.size() + " 个源）");
                    return got.toArray(new String[0][]);
                }
            } catch (Exception ignored) {
            }
        }
        log.add("源清单：仓库清单拿不到，使用 App 内置的 " + PUBLIC_SOURCES.length + " 个源");
        return PUBLIC_SOURCES;
    }

    static boolean allowedSourceUrl(String url) {
        if (url == null || url.length() > 300 || !url.startsWith("https://")) return false;
        if (url.matches(".*[\\s\\\\@].*")) return false;
        return url.startsWith("https://raw.githubusercontent.com/")
                || url.startsWith("https://cdn.jsdelivr.net/gh/")
                || url.startsWith("https://gist.githubusercontent.com/");
    }

    /** raw 地址 → [raw, jsDelivr, ghfast.top]。非 GitHub raw 的地址原样返回。 */
    static List<String> mirrorsOf(String raw) {
        List<String> out = new ArrayList<>();
        out.add(raw);
        String prefix = "https://raw.githubusercontent.com/";
        if (raw.startsWith(prefix)) {
            String[] seg = raw.substring(prefix.length()).split("/", 4); // owner/repo/branch/path
            if (seg.length == 4) {
                out.add("https://cdn.jsdelivr.net/gh/" + seg[0] + "/" + seg[1] + "@" + seg[2] + "/" + seg[3]);
            }
            out.add("https://ghfast.top/" + raw);
        }
        return out;
    }


    /** loadNodes 跳过的条目（tag + 原因），供界面日志诊断用。 */
    // v3.0：loadNodes 会被界面、实测、后台维护线程同时调用，必须是线程安全的列表
    public static final List<String> lastSkips =
            java.util.Collections.synchronizedList(new ArrayList<String>());

    /**
     * AI 出口闸门的探针。必须是「被地区封锁时返回 403、正常时返回 200」的地址。
     *
     * libv2ray 的 measureInstDelay 只把 200 / 204 算成功（其它状态码返回 -1），
     * 所以这两个 URL 能真实区分「节点能不能用 ChatGPT / Claude」：
     * 机房 IP 被 Cloudflare 判定不支持地区时是 403 → 判失败。
     * 用 /cdn-cgi/trace 而不是首页：首页对无 UA 的 Go 客户端会走挑战页。
     */
    public static final String[] AI_PROBES = {
            "https://chatgpt.com/cdn-cgi/trace",
            "https://claude.ai/cdn-cgi/trace",
    };

    public static final class Node {
        public final String tag;          // g3 / i0 ……（同时用于 proxy-<tag> 出站标签）
        public final String name;         // 展示名，如 "g3 · IT vless"
        public final String key;          // server:port/proto 的短哈希，跨重排/重导入稳定
        public final boolean imported;
        public boolean cg;                // 过得了 ChatGPT/Claude 地区闸门
        public final JSONObject outbound; // tag 已改为 proxy-<tag>

        Node(String tag, String name, boolean imported, boolean cg, JSONObject outbound) {
            this.tag = tag;
            this.name = name;
            this.imported = imported;
            this.cg = cg;
            this.outbound = outbound;
            this.key = nodeKey(outbound);
        }
    }

    /**
     * 节点身份：完整 outbound（去掉运行时 tag）的 SHA-256。
     * 同端点不同凭据、传输或 TLS 参数不得共享健康度与 AI 闸门结果。
     */
    public static String nodeKey(JSONObject ob) {
        try {
            return NodeConfigCodec.outboundIdentity(ob);
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String sha1hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", d[i]));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode());
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
        Set<String> kernelBad = loadKernelBad(ctx);
        int idx = 0;
        for (String uri : uris) {
            String tag = "i" + idx;
            Node node = nodeFromUri(uri, tag, true);
            if (node == null) {
                lastSkips.add("导入第 " + (idx + 1) + " 个无法解析");
                idx++;
                continue;
            }
            idx++;
            String fp = outboundFingerprint(node.outbound);
            if (fp != null && kernelBad.contains(fp)) {
                lastSkips.add(tag + " 未通过内核预检");
                continue;
            }
            out.add(node);
        }
        // 本机实测过的闸门结果优先于内置 JSON 里的静态标记：
        // 公开源导入的节点没有 cg 字段，全靠这一步才有资格进 cg-balancer。
        Set<String> gated = loadGateKeys(ctx);
        for (Node n : out) {
            if (!n.cg && gated.contains(n.key)) n.cg = true;
            // v3.1：本机实测发现要分片才能连通的节点（SNI 被封），运行与后续测试都带上分片
            try {
                NodeHealth.Entry h = NodeHealth.get(ctx, n.key);
                if (h != null && h.frag) NodeConfigCodec.applyTlsFragment(n.outbound);
            } catch (Throwable ignored) {
            }
        }
        return out;
    }

    /**
     * 一条分享链接 → Node（tag 由调用方给）。导入路径与公开源候选共用，保证候选阶段
     * 测出的健康度（按 nodeKey）入池后原样沿用。解析失败返回 null。
     */
    public static Node nodeFromUri(String uri, String tag, boolean imported) {
        JSONObject ob;
        try {
            ob = parseUri(uri);
        } catch (Throwable t) {
            ob = null;
        }
        if (ob == null) return null;
        try {
            ob.put("tag", "proxy-" + tag);
            // 公开源/第三方订阅里的 allowInsecure=1 等于让节点静默关掉证书校验，
            // 中间人可以随便截。导入节点一律不信这个字段，只信内置节点自带的配置。
            if (imported) stripAllowInsecure(ob);
        } catch (Exception e) {
            return null;
        }
        return new Node(tag, tag + " · " + displayName(ob), imported, false, ob);
    }

    /** 出站的服务器地址 {host, port}；取不到返回 null。 */
    public static String[] endpoint(JSONObject ob) {
        try {
            JSONObject s = ob.optJSONObject("settings");
            JSONArray v = s != null ? s.optJSONArray("vnext") : null;
            JSONArray sv = s != null ? s.optJSONArray("servers") : null;
            JSONObject ep = null;
            if (v != null && v.length() > 0) ep = v.optJSONObject(0);
            else if (sv != null && sv.length() > 0) ep = sv.optJSONObject(0);
            else if (s != null && s.has("address")) ep = s;
            if (ep == null) return null;
            String host = ep.optString("address", "").trim();
            int port = ep.optInt("port", 0);
            if (host.isEmpty() || port < 1 || port > 65535) return null;
            return new String[]{host, String.valueOf(port)};
        } catch (Throwable t) {
            return null;
        }
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

    // ---------------------------------------------------------- 内核预检

    /**
     * 内核预检缓存：只记「配置非法」的 outbound 指纹，不记可用性结果。
     *
     * 内核是整份配置要么全用、要么全不用，导入一条内核不认的节点（旧版加密、
     * REALITY 参数错、未知传输…）会让整个节点池起不来。这里用
     * {@code Libv2ray.measureOutboundDelay} 做单节点 Dry-Run：配置加载/实例创建/
     * 启动任一步失败都算非法；之后故意传一个 parse 不了的 URL，让内核在
     * {@code http.NewRequest} 阶段停住，不产生任何网络请求。
     */
    private static final String KEY_BAD = "kernel_bad_v1";
    /** 这个 URL 在 http.NewRequest 就会失败，Dry-Run 不会发出流量。 */
    private static final String DRY_RUN_URL = "http://[::1";
    private static final int MAX_BAD_CACHE = 400;

    /** 配置类错误前缀来自 libv2ray_utils.go；其它异常（含 URL 解析失败）视为配置可用。 */
    static boolean isConfigError(String message) {
        String m = message == null ? "" : message.toLowerCase(Locale.ROOT);
        return m.contains("config load error")
                || m.contains("instance creation failed")
                || m.contains("startup failed");
    }

    /** true = 内核拒绝这条出站的配置本身。不联网，可在任意后台线程调用。 */
    public static boolean kernelRejects(JSONObject outbound) {
        try {
            JSONObject probe = new JSONObject(outbound.toString());
            probe.put("tag", "proxy-probe");
            Libv2ray.measureOutboundDelay(measureConfigOf(probe), DRY_RUN_URL);
            return false;
        } catch (Throwable t) {
            return isConfigError(String.valueOf(t.getMessage()));
        }
    }

    /** 节点指纹：去掉 tag 后的 outbound JSON 的 SHA-1。解析/字段顺序稳定。 */
    public static String outboundFingerprint(JSONObject outbound) {
        try {
            JSONObject copy = new JSONObject(outbound.toString());
            copy.remove("tag");
            return sha1hex(copy.toString());
        } catch (Throwable t) {
            return null;
        }
    }

    private static Set<String> loadKernelBad(Context ctx) {
        Set<String> out = new HashSet<>();
        try {
            Set<String> raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .getStringSet(KEY_BAD, null);
            if (raw != null) {
                for (String e : raw) {
                    if (e.startsWith("v1:")) out.add(e.substring(3));
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private static void markKernelBad(Context ctx, List<String> fingerprints) {
        if (fingerprints == null || fingerprints.isEmpty()) return;
        Set<String> set = new HashSet<>();
        for (String fp : loadKernelBad(ctx)) set.add("v1:" + fp);
        for (String fp : fingerprints) {
            if (fp != null && !fp.isEmpty()) set.add("v1:" + fp);
        }
        if (set.size() > MAX_BAD_CACHE) set.clear(); // 异常膨胀时重建，别让 prefs 无限长
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putStringSet(KEY_BAD, set).apply();
    }

    public static void clearKernelBad(Context ctx) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().remove(KEY_BAD).apply();
    }

    /**
     * 导入前筛一遍：能解析 + 内核 Dry-Run 通过才进池。重复 URI 直接保留，不重复测。
     * 必须在后台线程调用；返回的列表交给 {@link #addImportedUris}。
     */
    public static List<String> screenImports(Context ctx, List<String> uris, List<String> log) {
        List<String> keep = new ArrayList<>();
        if (uris == null || uris.isEmpty()) return keep;
        Set<String> existing = new HashSet<>(loadImportedUris(ctx));
        Set<String> cachedBad = loadKernelBad(ctx);
        List<String> newBad = new ArrayList<>();
        int parseRejected = 0;
        int kernelRejected = 0;
        try {
            Libv2ray.initCoreEnv(ctx.getFilesDir().getAbsolutePath(), "");
        } catch (Throwable ignored) {
        }
        for (String raw : uris) {
            String uri = raw == null ? "" : raw.trim();
            if (uri.isEmpty()) continue;
            if (existing.contains(uri)) {
                keep.add(uri);
                continue;
            }
            JSONObject ob = parseUri(uri);
            if (ob == null) {
                parseRejected++;
                continue;
            }
            String fp = outboundFingerprint(ob);
            if (fp != null && cachedBad.contains(fp)) {
                kernelRejected++;
                continue;
            }
            if (kernelRejects(ob)) {
                kernelRejected++;
                if (fp != null) newBad.add(fp);
                continue;
            }
            keep.add(uri);
        }
        // 整批全部被内核拒绝时先不写缓存：可能是内核环境异常而不是节点全坏。
        if (!keep.isEmpty()) markKernelBad(ctx, newBad);
        if (log != null && (parseRejected + kernelRejected) > 0) {
            log.add("预检剔除 " + (parseRejected + kernelRejected)
                    + " 条（无法解析 " + parseRejected + "，内核拒绝 " + kernelRejected + "）");
        }
        return keep;
    }

    /**
     * VPN 启动被内核拒绝后的补救：找出导入节点里配置非法的那些并拉黑，
     * 下次启动就不再带它们。返回新拉黑数量。
     */
    public static int quarantineInvalidImports(Context ctx) {
        Set<String> cachedBad = loadKernelBad(ctx);
        List<String> newBad = new ArrayList<>();
        int ok = 0;
        try {
            Libv2ray.initCoreEnv(ctx.getFilesDir().getAbsolutePath(), "");
        } catch (Throwable ignored) {
        }
        for (String uri : loadImportedUris(ctx)) {
            JSONObject ob = parseUri(uri);
            if (ob == null) continue;
            String fp = outboundFingerprint(ob);
            if (fp != null && cachedBad.contains(fp)) continue;
            if (kernelRejects(ob)) {
                if (fp != null) newBad.add(fp);
            } else {
                ok++;
            }
        }
        if (ok > 0) markKernelBad(ctx, newBad);
        return newBad.size();
    }

    public static void saveImportedUris(Context ctx, List<String> uris) {
        JSONArray arr = new JSONArray();
        for (String u : uris) arr.put(u);
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putString(KEY_URIS, arr.toString()).apply();
    }

    // -------------------------------------------------- AI 出口闸门（本机实测结果）

    private static final String KEY_GATE = "gate_ok";

    /** 闸门结果有效期（天）。免费节点换手很快，太久以前的结果反而误导。 */
    // 免费池里的干净 IP 几小时就可能被刷到 403，7 天等于让死节点继续背一周流量。
    public static final int GATE_TTL_DAYS = 1;

    private static long today() {
        return System.currentTimeMillis() / 86400000L;
    }

    /** 仍有效的「过闸门」节点 key 集合（条目格式 key@epochDay）。 */
    public static Set<String> loadGateKeys(Context ctx) {
        Set<String> out = new HashSet<>();
        SharedPreferences sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        Set<String> raw = new HashSet<>();
        try {
            Set<String> got = sp.getStringSet(KEY_GATE, null);
            if (got != null) raw.addAll(got);
        } catch (Exception ignored) {
        }
        long now = today();
        for (String e : raw) {
            int at = e.lastIndexOf('@');
            if (at <= 0) continue;
            try {
                if (now - Long.parseLong(e.substring(at + 1)) <= GATE_TTL_DAYS) {
                    out.add(e.substring(0, at));
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return out;
    }

    /** 记录一个节点的闸门结果；失败就把它从白名单里摘掉。 */
    public static void saveGate(Context ctx, String key, boolean ok) {
        if (key == null || key.isEmpty()) return;
        SharedPreferences sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        Set<String> next = new HashSet<>();
        try {
            Set<String> got = sp.getStringSet(KEY_GATE, null);
            if (got != null) {
                for (String e : got) {
                    int at = e.lastIndexOf('@');
                    if (at > 0 && e.substring(0, at).equals(key)) continue; // 覆盖旧结果
                    next.add(e);
                }
            }
        } catch (Exception ignored) {
        }
        if (ok) next.add(key + "@" + today());
        sp.edit().putStringSet(KEY_GATE, next).apply();
    }

    /** 合并导入（按 server:port/协议 去重、按健康度排序、限 {@link #MAX_IMPORTED}），返回新增条数。 */
    public static int addImportedUris(Context ctx, List<String> newUris) {
        // 所有导入池写操作统一走 NodePool（同一把锁），界面导入与后台维护可能并发
        return NodePool.addUris(ctx, newUris);
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
        java.net.URI target;
        try {
            target = SubscriptionGuard.check(url);
        } catch (SubscriptionGuard.Rejected rejected) {
            // Untrusted input decides where the app connects; refuse before DNS.
            throw new IllegalArgumentException("订阅地址不可用：" + rejected.reason);
        }
        HttpURLConnection c = null;
        for (int hop = 0; hop <= SubscriptionGuard.MAX_REDIRECTS; hop++) {
            c = (HttpURLConnection) target.toURL().openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(20000);
            // Redirects are followed by hand so every hop passes the same guard;
            // otherwise a public URL could bounce the app into 127.0.0.1.
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36");
            // SubscriptionGuard 只做字符串检查；域名解析成 127.0.0.1 / 169.254.x 的
            // rebinding 攻击必须在这里再拦一次（拿的是真实解析结果）。
            SubscriptionGuard.checkResolved(target.getHost());
            int code = c.getResponseCode();
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                String location = c.getHeaderField("Location");
                c.disconnect();
                if (location == null) throw new IllegalStateException("HTTP " + code + " 无 Location");
                if (hop == SubscriptionGuard.MAX_REDIRECTS) {
                    throw new IllegalStateException("重定向次数过多");
                }
                java.net.URI next;
                try {
                    // Location 可能是相对路径（/v2ray.txt），直接当绝对 URI 校验会误拒。
                    next = target.resolve(location.trim());
                    if ("https".equalsIgnoreCase(target.getScheme())
                            && !"https".equalsIgnoreCase(next.getScheme())) {
                        throw new IllegalStateException("不允许从 HTTPS 降级到 HTTP 重定向");
                    }
                    target = SubscriptionGuard.check(next.toString());
                } catch (SubscriptionGuard.Rejected rejected) {
                    throw new IllegalStateException("重定向被拒绝：" + rejected.reason);
                }
                continue;
            }
            if (code != 200) throw new IllegalStateException("HTTP " + code);
            break;
        }
        if (c == null) throw new IllegalStateException("没有可用的连接");
        InputStream in = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        boolean truncated = false;
        try {
        in = c.getInputStream();
        byte[] buf = new byte[16384];
        int n;
        int total = 0;
        while ((n = in.read(buf)) > 0) {
            total += n;
            // A hostile or broken subscription must not exhaust the phone's RAM
            // (review C11). v3.0: 超过 2 MB 不再整源作废，而是截断——大聚合列表是按行的
            // 明文链接，前 2 MB 已经是几千条候选；base64 整段编码的源截断后解不开，下面会报错。
            if (total > 2 * 1024 * 1024) {
                truncated = true;
                break;
            }
            bos.write(buf, 0, n);
        }
        } finally {
            if (in != null) try { in.close(); } catch (Exception ignored) {}
            c.disconnect();
        }
        String body = bos.toString("UTF-8").trim();
        if (truncated) {
            if (!body.contains("://")) throw new IllegalStateException("订阅超过 2 MB 且是整段 base64，无法截断使用");
            int nl = body.lastIndexOf('\n');
            if (nl > 0) body = body.substring(0, nl); // 丢掉被截断的最后一行
        }
        if (!body.contains("://")) {
            String dec = tryB64(body);
            if (dec != null) body = dec;
        }
        return splitUris(body);
    }

    /**
     * 抓取全部公开源（必须在后台线程调用）。v3.0：6 路并发、每个源依次试 raw → jsDelivr → ghfast
     * 镜像，**所有源都抓**（v2.x 凑满 120 条就停，排在后面的大陆向源永远轮不到）。
     * 按 server:port/协议 去重后最多返回 {@link #CANDIDATE_MAX} 条候选；单源最多 {@link #PER_SOURCE}。
     * 返回的只是候选，是否入池由 {@link NodePool#refreshFromPublic} 的本机实测决定。
     */
    public static List<String> fetchPublicSources(List<String> log) {
        final String[][] sources = resolveSources(log);
        final int count = sources.length;
        final List<List<String>> got = new ArrayList<>();
        final String[] notes = new String[count];
        for (int i = 0; i < count; i++) got.add(null);
        ExecutorService pool = Executors.newFixedThreadPool(6);
        for (int i = 0; i < count; i++) {
            final int idx = i;
            pool.execute(() -> {
                String name = sources[idx][0];
                List<String> urls = mirrorsOf(sources[idx][1]);
                String err = "?";
                for (int k = 0; k < urls.size(); k++) {
                    try {
                        List<String> list = fetchSubscription(urls.get(k));
                        synchronized (got) {
                            got.set(idx, list);
                        }
                        String via = k == 0 ? "" : (k == 1 ? "（jsDelivr）" : "（镜像）");
                        notes[idx] = name + via + "：" + list.size() + " 条";
                        return;
                    } catch (Exception e) {
                        err = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                    }
                }
                notes[idx] = name + " 失败：" + err;
            });
        }
        pool.shutdown();
        try {
            pool.awaitTermination(150, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
        pool.shutdownNow();

        LinkedHashMap<String, String> byKey = new LinkedHashMap<>();
        int hyTotal = 0;
        for (int i = 0; i < count; i++) {
            List<String> list;
            synchronized (got) {
                list = got.get(i);
            }
            int added = 0;
            if (list != null) {
                // v3.2：按协议轮流取。大聚合源前几百条往往全是同一种协议（Barabama 前 700 条是
                // vless），按顺序取 80 条就一条 Hysteria2 都轮不到。
                for (String u : interleaveBySchema(list)) {
                    if (added >= PER_SOURCE || byKey.size() >= CANDIDATE_MAX) break;
                    JSONObject ob = parseUri(u);
                    if (ob == null) continue;
                    boolean hy = "hysteria".equals(ob.optString("protocol", ""));
                    // QUIC 节点不能 TCP 预筛，死节点要等内核超时（最长约 24 秒），限量放进候选
                    if (hy && hyTotal >= HY_CANDIDATE_MAX) continue;
                    String k = nodeKey(ob);
                    if (byKey.containsKey(k)) continue;
                    byKey.put(k, u);
                    added++;
                    if (hy) hyTotal++;
                }
            }
            String note = notes[i] != null ? notes[i] : sources[i][0] + " 超时";
            log.add(list != null ? note + "，收下 " + added : note);
        }
        if (hyTotal > 0) log.add("其中 Hysteria2 候选 " + hyTotal + " 个");
        return new ArrayList<>(byKey.values());
    }

    /** 一次补充最多放进多少个 Hysteria2 候选。 */
    private static final int HY_CANDIDATE_MAX = 48;

    /** 按 scheme（vless/vmess/ss/trojan/hysteria2…）分桶后轮流取，保持各桶内原顺序。 */
    static List<String> interleaveBySchema(List<String> uris) {
        LinkedHashMap<String, List<String>> buckets = new LinkedHashMap<>();
        for (String u : uris) {
            int p = u.indexOf("://");
            String k = p > 0 ? u.substring(0, p).toLowerCase(Locale.ROOT) : "";
            if ("hy2".equals(k)) k = "hysteria2";
            List<String> b = buckets.get(k);
            if (b == null) {
                b = new ArrayList<>();
                buckets.put(k, b);
            }
            b.add(u);
        }
        List<String> out = new ArrayList<>(uris.size());
        int i = 0;
        boolean any = true;
        while (any) {
            any = false;
            for (List<String> b : buckets.values()) {
                if (i < b.size()) {
                    out.add(b.get(i));
                    any = true;
                }
            }
            i++;
        }
        return out;
    }

    /** 小文本 GET（源清单用）：过 SubscriptionGuard、不跟随重定向、最多 64 KB。 */
    static String fetchText(String url, int timeoutMs) throws Exception {
        java.net.URI target = SubscriptionGuard.check(url);
        SubscriptionGuard.checkResolved(target.getHost());
        HttpURLConnection c = (HttpURLConnection) target.toURL().openConnection();
        c.setConnectTimeout(Math.min(timeoutMs, 4000));
        c.setReadTimeout(timeoutMs);
        c.setInstanceFollowRedirects(false);
        c.setRequestProperty("User-Agent", "PhoneProxy");
        try {
            if (c.getResponseCode() != 200) throw new IllegalStateException("HTTP " + c.getResponseCode());
            InputStream in = c.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
                if (bos.size() > 65536) throw new IllegalStateException("too large");
            }
            in.close();
            return bos.toString("UTF-8");
        } finally {
            c.disconnect();
        }
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

    /** 单个 outbound 的最小测量配置（给measureOutboundDelay用，等于一次单节点 Dry-Run）。 */
    public static String measureConfigOf(JSONObject outbound) throws Exception {
        return NodeConfigCodec.measureConfigOf(outbound);
    }

    /**
     * 完整运行配置：TUN 入站 + 全部节点 + 直连 + DNS 出站。
     * selected = "auto" 走 observatory+balancer（leastPing），否则固定到该节点。
     */
    public static String fullConfig(List<Node> nodes, String selected) throws Exception {
        if (nodes == null || nodes.isEmpty()) throw new IllegalStateException("没有可用节点");
        List<JSONObject> proxies = new ArrayList<>();
        Set<String> cgTags = new HashSet<>();
        for (Node n : nodes) {
            proxies.add(n.outbound);
            if (n.cg) cgTags.add(n.tag);
        }
        return NodeConfigCodec.fullConfig(proxies, cgTags, selected);
    }

    /** 同上，带 balancer 兜底出站（完整 tag，如 proxy-i3），见 NodeConfigCodec。 */
    public static String fullConfig(List<Node> nodes, String selected, String fallbackTag)
            throws Exception {
        if (nodes == null || nodes.isEmpty()) throw new IllegalStateException("没有可用节点");
        List<JSONObject> proxies = new ArrayList<>();
        Set<String> cgTags = new HashSet<>();
        for (Node n : nodes) {
            proxies.add(n.outbound);
            if (n.cg) cgTags.add(n.tag);
        }
        return NodeConfigCodec.fullConfig(proxies, cgTags, selected, fallbackTag);
    }

    /** v3.1：再带 leastLoad 代价系数（完整 tag → 系数），见 NodePool.costsFor。 */
    public static String fullConfig(List<Node> nodes, String selected, String fallbackTag,
                                    java.util.Map<String, Double> costs) throws Exception {
        if (nodes == null || nodes.isEmpty()) throw new IllegalStateException("没有可用节点");
        List<JSONObject> proxies = new ArrayList<>();
        Set<String> cgTags = new HashSet<>();
        for (Node n : nodes) {
            proxies.add(n.outbound);
            if (n.cg) cgTags.add(n.tag);
        }
        return NodeConfigCodec.fullConfig(proxies, cgTags, selected, fallbackTag, costs);
    }

    // ---------------------------------------------------------- 分享链接解析

    /** 把一条分享链接解析成 Xray 出站（tag 未设置）。不支持/非法返回 null。 */
    public static JSONObject parseUri(String uri) {
        return NodeConfigCodec.parseUri(uri);
    }

    /** 整段 base64 的订阅/剪贴板内容先解码。 */
    static String tryB64(String s) {
        return NodeConfigCodec.tryB64(s);
    }

    private static String displayName(JSONObject ob) {
        return NodeConfigCodec.describe(ob);
    }

    /** 导入节点的 TLS/REALITY 一律关掉 allowInsecure（解析器已置 false，这里兜底）。 */
    private static void stripAllowInsecure(JSONObject ob) throws Exception {
        JSONObject stream = ob.optJSONObject("streamSettings");
        if (stream == null) return;
        JSONObject tls = stream.optJSONObject("tlsSettings");
        if (tls != null) tls.put("allowInsecure", false);
        JSONObject reality = stream.optJSONObject("realitySettings");
        if (reality != null) reality.put("allowInsecure", false);
    }
}
