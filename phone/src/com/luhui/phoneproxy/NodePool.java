package com.luhui.phoneproxy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 节点池维护（v3.0 新增）：只让「本机实测能连上」的节点进运行配置，导入池自动去死补新。
 *
 * <p>导入池（SharedPreferences 里的 URI 列表）的所有写操作都经过这里并持同一把锁，
 * 因为界面导入、启动时自动补充、后台维护、实测收尾回调可能在不同线程同时改它。
 */
public final class NodePool {

    /** 运行配置里最多放多少个出口：observatory 每轮都要探全部成员。 */
    public static final int RUNTIME_MAX = 30;
    /** 可用数低于这个值，后台维护会去公开源补充。 */
    public static final int MIN_ALIVE_AUTOREFRESH = 5;
    /** 两次自动补充的最小间隔，避免网络整体不通时反复抓取。 */
    public static final long REFRESH_MIN_GAP_MS = 2L * 3600 * 1000;

    private static final String PREFS = "pool";
    private static final String KEY_LAST_REFRESH = "last_refresh";
    private static final Object LOCK = new Object();

    private NodePool() {
    }

    // ------------------------------------------------------------ 查询

    /** 30 分钟内实测可用的节点，按延迟升序。 */
    public static List<ConfigBuilder.Node> aliveFresh(Context ctx, List<ConfigBuilder.Node> nodes) {
        final long now = System.currentTimeMillis();
        final Map<String, Long> ms = new HashMap<>();
        List<ConfigBuilder.Node> out = new ArrayList<>();
        if (nodes == null) return out;
        for (ConfigBuilder.Node n : nodes) {
            NodeHealth.Entry e = NodeHealth.get(ctx, n.key);
            if (NodeHealth.aliveFresh(e, now)) {
                out.add(n);
                ms.put(n.tag, e.ms);
            }
        }
        Collections.sort(out, (a, b) -> Long.compare(ms.get(a.tag), ms.get(b.tag)));
        return out;
    }

    /** 实测最近一次延迟；没有/不可用返回 -1。 */
    public static long msOf(Context ctx, ConfigBuilder.Node n) {
        NodeHealth.Entry e = NodeHealth.get(ctx, n.key);
        return e != null && e.ms > 0 ? e.ms : -1;
    }

    /** 按健康度排序：新鲜可用（延迟升序）→ 未测/过期 → 新鲜不可用。 */
    public static List<ConfigBuilder.Node> sortedForDisplay(Context ctx, List<ConfigBuilder.Node> nodes) {
        final long now = System.currentTimeMillis();
        final Map<String, int[]> rank = new HashMap<>();
        final Map<String, Long> ms = new HashMap<>();
        for (ConfigBuilder.Node n : nodes) {
            NodeHealth.Entry e = NodeHealth.get(ctx, n.key);
            rank.put(n.tag, new int[]{NodeHealth.rank(e, now)});
            ms.put(n.tag, e != null && e.ms > 0 ? e.ms : Long.MAX_VALUE / 4);
        }
        List<ConfigBuilder.Node> out = new ArrayList<>(nodes);
        Collections.sort(out, (a, b) -> {
            int c = Integer.compare(rank.get(a.tag)[0], rank.get(b.tag)[0]);
            return c != 0 ? c : Long.compare(ms.get(a.tag), ms.get(b.tag));
        });
        return out;
    }

    /**
     * 运行配置成员：可用节点里最快的 {@link #RUNTIME_MAX} 个；固定节点模式下保证所选节点在内。
     * alive 需已按延迟升序（{@link #aliveFresh} 的返回值）。
     */
    public static List<ConfigBuilder.Node> runtimeMembers(List<ConfigBuilder.Node> alive,
                                                          List<ConfigBuilder.Node> all,
                                                          String selection) {
        List<ConfigBuilder.Node> out = new ArrayList<>();
        for (ConfigBuilder.Node n : alive) {
            if (out.size() >= RUNTIME_MAX) break;
            out.add(n);
        }
        if (selection != null && !selection.isEmpty() && !"auto".equals(selection)) {
            ConfigBuilder.Node sel = ConfigBuilder.find(all, selection);
            if (sel != null && ConfigBuilder.find(out, sel.tag) == null) out.add(0, sel);
        }
        return out;
    }

    public static boolean refreshAllowed(Context ctx) {
        long last = prefs(ctx).getLong(KEY_LAST_REFRESH, 0);
        return System.currentTimeMillis() - last >= REFRESH_MIN_GAP_MS;
    }

    // ------------------------------------------------------------ 写导入池

    /**
     * 合并进导入池：按 server:port/协议 去重（公开源里同一台机器常出现几十次、只是备注不同），
     * 按健康度排序后截到上限，超出的优先丢掉已知不可用的。返回真正留在池里的新条目数。
     */
    public static int addUris(Context ctx, List<String> newUris) {
        if (newUris == null || newUris.isEmpty()) return 0;
        synchronized (LOCK) {
            LinkedHashMap<String, String> byKey = new LinkedHashMap<>();
            for (String u : ConfigBuilder.loadImportedUris(ctx)) {
                String k = keyOfUri(u);
                if (k != null && !byKey.containsKey(k)) byKey.put(k, u);
            }
            Set<String> added = new HashSet<>();
            for (String raw : newUris) {
                String u = raw == null ? "" : raw.trim();
                if (u.isEmpty()) continue;
                String k = keyOfUri(u);
                if (k == null || byKey.containsKey(k)) continue;
                byKey.put(k, u);
                added.add(u);
            }
            List<String> merged = sortUrisByHealth(ctx, new ArrayList<>(byKey.values()));
            while (merged.size() > ConfigBuilder.MAX_IMPORTED) merged.remove(merged.size() - 1);
            ConfigBuilder.saveImportedUris(ctx, merged);
            int kept = 0;
            for (String u : merged) if (added.contains(u)) kept++;
            return kept;
        }
    }

    /** 删掉连续失败 ≥ minFails 次的导入节点，返回删除数。内置节点不删，只是不进运行配置。 */
    public static int pruneDeadImports(Context ctx, int minFails) {
        synchronized (LOCK) {
            List<String> keep = new ArrayList<>();
            int removed = 0;
            for (String u : ConfigBuilder.loadImportedUris(ctx)) {
                String k = keyOfUri(u);
                NodeHealth.Entry e = k == null ? null : NodeHealth.get(ctx, k);
                if (k == null || (e != null && e.ms <= 0 && e.fails >= minFails)) {
                    removed++;
                } else {
                    keep.add(u);
                }
            }
            if (removed > 0) ConfigBuilder.saveImportedUris(ctx, sortUrisByHealth(ctx, keep));
            return removed;
        }
    }

    /** 导入池按最新实测重排（tag i0 永远是当前最快的导入节点）。 */
    public static void resort(Context ctx) {
        synchronized (LOCK) {
            ConfigBuilder.saveImportedUris(ctx,
                    sortUrisByHealth(ctx, ConfigBuilder.loadImportedUris(ctx)));
        }
    }

    // ------------------------------------------------------------ 公开源补充

    /**
     * 抓全部公开源 → 内核预检 → 本机实测 → 只把能连上的放进导入池。
     *
     * <p>和 v2.x 的区别：v2.x 依次抓源、凑满 120 条就停（排在前面的是伊朗向聚合源，
     * 后面针对大陆的源根本轮不到），抓到就直接入池、从不测连通性。
     *
     * @param budgetMs 实测阶段最多阻塞多久；没测完的在后台继续，测完调用 onLateMerge
     * @param enough   &gt;0：找到这么多可用节点就先返回（启动时用）
     * @return 本次新入池的节点数
     */
    public static int refreshFromPublic(Context ctx, List<String> logs, long budgetMs, int enough,
                                        NodeTester.Callback cb, final Runnable onLateMerge) {
        final Context app = ctx.getApplicationContext();
        prefs(app).edit().putLong(KEY_LAST_REFRESH, System.currentTimeMillis()).apply();

        List<String> fetched = ConfigBuilder.fetchPublicSources(logs);
        if (fetched.isEmpty()) {
            logs.add("公开源一个都没抓到：GitHub 与各镜像在当前网络都连不上。可以换个网络再试，或粘贴自己的订阅");
            return 0;
        }
        Set<String> have = new HashSet<>();
        for (String u : ConfigBuilder.loadImportedUris(app)) {
            String k = keyOfUri(u);
            if (k != null) have.add(k);
        }
        List<String> fresh = new ArrayList<>();
        for (String u : fetched) {
            String k = keyOfUri(u);
            if (k != null && !have.contains(k)) fresh.add(u);
        }
        List<String> screened = ConfigBuilder.screenImports(app, fresh, logs);
        final List<ConfigBuilder.Node> cands = new ArrayList<>();
        final Map<String, String> uriByTag = new HashMap<>();
        int i = 0;
        for (String u : screened) {
            ConfigBuilder.Node n = ConfigBuilder.nodeFromUri(u, "c" + i, true);
            if (n == null) continue;
            cands.add(n);
            uriByTag.put(n.tag, u);
            i++;
        }
        if (cands.isEmpty()) {
            logs.add("抓到的链接都没通过解析/内核预检");
            return 0;
        }
        logs.add("候选 " + cands.size() + " 个（已去重、已排除池内已有），在本机网络逐个实测…");
        Runnable late = () -> {
            int more = mergeAlive(app, cands, uriByTag);
            if (more > 0 && onLateMerge != null) onLateMerge.run();
        };
        Map<String, Long> res = NodeTester.run(app, cands, budgetMs, enough, cb, late);
        int added = mergeAlive(app, cands, uriByTag);
        int alive = 0;
        for (Long v : res.values()) if (v != null && v > 0) alive++;
        logs.add("实测 " + res.size() + "/" + cands.size() + "：能连上 " + alive + " 个，新入池 " + added
                + (res.size() < cands.size() ? "（其余在后台继续测，测通的会自动入池）" : ""));
        return added;
    }

    private static int mergeAlive(Context app, List<ConfigBuilder.Node> cands,
                                  Map<String, String> uriByTag) {
        List<ConfigBuilder.Node> ok = aliveFresh(app, cands);
        if (ok.isEmpty()) return 0;
        List<String> uris = new ArrayList<>();
        for (ConfigBuilder.Node n : ok) {
            String u = uriByTag.get(n.tag);
            if (u != null) uris.add(u);
        }
        return addUris(app, uris);
    }

    // ------------------------------------------------------------ 小工具

    static String keyOfUri(String uri) {
        try {
            JSONObject ob = ConfigBuilder.parseUri(uri);
            return ob == null ? null : ConfigBuilder.nodeKey(ob);
        } catch (Throwable t) {
            return null;
        }
    }

    private static List<String> sortUrisByHealth(Context ctx, List<String> uris) {
        final long now = System.currentTimeMillis();
        final Map<String, Long> score = new HashMap<>();
        for (String u : uris) {
            String k = keyOfUri(u);
            NodeHealth.Entry e = k == null ? null : NodeHealth.get(ctx, k);
            int r = NodeHealth.rank(e, now);
            long ms = e != null && e.ms > 0 ? Math.min(e.ms, 999999L) : 999999L;
            score.put(u, r * 1000000L + ms);
        }
        List<String> out = new ArrayList<>(uris);
        Collections.sort(out, (a, b) -> Long.compare(score.get(a), score.get(b)));
        return out;
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
