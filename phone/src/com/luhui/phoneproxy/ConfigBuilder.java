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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

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
     * 节点身份：server:port/protocol 的哈希。
     *
     * 不能用 tag 当键：导入节点的 tag 是 i0/i1… 按位置生成，用户删掉一个或换一次源，
     * 后面所有节点的 tag 都会平移，闸门结果就会张冠李戴（把能过 AI 的标记贴到
     * 不能过的节点上，比没有标记更糟）。
     */
    public static String nodeKey(JSONObject ob) {
        String id = "";
        try {
            JSONObject s = ob.optJSONObject("settings");
            JSONArray v = s != null ? s.optJSONArray("vnext") : null;
            JSONArray sv = s != null ? s.optJSONArray("servers") : null;
            JSONObject ep = null;
            if (v != null && v.length() > 0) ep = v.optJSONObject(0);
            else if (sv != null && sv.length() > 0) ep = sv.optJSONObject(0);
            if (ep != null) {
                id = ep.optString("address", "") + ":" + ep.optInt("port", 0)
                        + "/" + ob.optString("protocol", "");
            }
        } catch (Throwable ignored) {
        }
        if (id.isEmpty()) id = ob.optString("tag", "");
        return sha1hex(id);
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
                // 公开源/第三方订阅里的 allowInsecure=1 等于让节点静默关掉证书校验，
                // 中间人可以随便截。导入节点一律不信这个字段，只信内置节点自带的配置。
                stripAllowInsecure(ob);
            } catch (Exception e) {
                continue;
            }
            String fp = outboundFingerprint(ob);
            if (fp != null && kernelBad.contains(fp)) {
                lastSkips.add(tag + " 未通过内核预检");
                continue;
            }
            out.add(new Node(tag, tag + " · " + displayName(ob), true, false, ob));
        }
        // 本机实测过的闸门结果优先于内置 JSON 里的静态标记：
        // 公开源导入的节点没有 cg 字段，全靠这一步才有资格进 cg-balancer。
        Set<String> gated = loadGateKeys(ctx);
        for (Node n : out) {
            if (!n.cg && gated.contains(n.key)) n.cg = true;
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
            c.setConnectTimeout(15000);
            c.setReadTimeout(25000);
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
        try {
        in = c.getInputStream();
        byte[] buf = new byte[16384];
        int n;
        int total = 0;
        while ((n = in.read(buf)) > 0) {
            total += n;
            // A hostile or broken subscription must not exhaust the phone's RAM
            // (review C11). 10 MB is far beyond any real share-link list.
            if (total > 2 * 1024 * 1024) {
                throw new IllegalStateException("订阅超过 2 MB，已中止");
            }
            bos.write(buf, 0, n);
        }
        } finally {
            if (in != null) try { in.close(); } catch (Exception ignored) {}
            c.disconnect();
        }
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
