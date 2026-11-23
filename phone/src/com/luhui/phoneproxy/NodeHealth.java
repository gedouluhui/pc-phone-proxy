package com.luhui.phoneproxy;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * 本机实测健康度（v3.0 新增）。
 *
 * <p>为什么要有它：v2.x 只有「内核能不能加载这条配置」的预检，从来不在用户自己的网络下
 * 测「连不连得上」。公开源和电脑端深测给的节点在中国大陆直连时大面积不可达，结果节点池
 * 144 个全是死节点、自动选线也选不出能用的（2026-11-23 实机截图）。
 *
 * <p>键是 {@link ConfigBuilder#nodeKey}（server:port/protocol 的哈希），跨重新导入、
 * 跨 tag 平移都稳定；候选阶段测出的结果在入池后直接沿用，不用重测。
 *
 * <p>只在内存里更新，{@link #flush} 时整体写回 SharedPreferences（一次实测几百条结果，
 * 逐条 apply 会反复序列化整张表）。
 */
public final class NodeHealth {

    private static final String PREFS = "health";
    private static final String KEY = "v1";

    /** 结论多久内算新鲜：免费节点半小时能死一半（PC 端 11-21 实测）。 */
    public static final long FRESH_MS = 30L * 60 * 1000;
    /** 连续失败多少次，导入节点就从池里删掉。 */
    public static final int PRUNE_FAILS = 3;
    private static final long KEEP_MS = 7L * 24 * 3600 * 1000;
    private static final int MAX_ENTRIES = 2000;

    public static final class Entry {
        /** 最近一次延迟（ms），&lt;=0 表示最近一次不可用。 */
        public long ms = -1;
        public long testedAt;
        public long okAt;
        /** 连续失败次数，成功一次清零。 */
        public int fails;

        Entry copy() {
            Entry e = new Entry();
            e.ms = ms;
            e.testedAt = testedAt;
            e.okAt = okAt;
            e.fails = fails;
            return e;
        }
    }

    private static final Map<String, Entry> MAP = new HashMap<>();
    private static boolean loaded = false;
    private static boolean dirty = false;

    private NodeHealth() {
    }

    private static void ensureLoaded(Context ctx) {
        if (loaded || ctx == null) return;
        loaded = true;
        try {
            String raw = ctx.getApplicationContext()
                    .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .getString(KEY, "{}");
            JSONObject o = new JSONObject(raw);
            Iterator<String> it = o.keys();
            while (it.hasNext()) {
                String k = it.next();
                JSONArray a = o.optJSONArray(k);
                if (a == null || a.length() < 4) continue;
                Entry e = new Entry();
                e.ms = a.optLong(0, -1);
                e.testedAt = a.optLong(1, 0);
                e.okAt = a.optLong(2, 0);
                e.fails = a.optInt(3, 0);
                MAP.put(k, e);
            }
        } catch (Throwable ignored) {
            // 坏数据就当没有测过，下一轮实测会重建
        }
    }

    /** 记一次实测结果（ms&lt;=0 = 失败）。只改内存，记得 {@link #flush}。 */
    public static synchronized void record(Context ctx, String key, long ms) {
        if (key == null || key.isEmpty()) return;
        ensureLoaded(ctx);
        long now = System.currentTimeMillis();
        Entry e = MAP.get(key);
        if (e == null) {
            e = new Entry();
            MAP.put(key, e);
        }
        e.testedAt = now;
        if (ms > 0) {
            e.ms = ms;
            e.okAt = now;
            e.fails = 0;
        } else {
            e.ms = -1;
            e.fails++;
        }
        dirty = true;
    }

    /** 拷贝一份；没测过返回 null。 */
    public static synchronized Entry get(Context ctx, String key) {
        if (key == null) return null;
        ensureLoaded(ctx);
        Entry e = MAP.get(key);
        return e == null ? null : e.copy();
    }

    public static synchronized void flush(Context ctx) {
        if (ctx == null) return;
        ensureLoaded(ctx);
        if (!dirty) return;
        long now = System.currentTimeMillis();
        if (MAP.size() > MAX_ENTRIES) {
            Iterator<Map.Entry<String, Entry>> it = MAP.entrySet().iterator();
            while (it.hasNext()) {
                if (now - it.next().getValue().testedAt > KEEP_MS) it.remove();
            }
        }
        if (MAP.size() > MAX_ENTRIES) {
            List<String> keys = new ArrayList<>(MAP.keySet());
            Collections.sort(keys, (a, b) -> Long.compare(MAP.get(a).testedAt, MAP.get(b).testedAt));
            int drop = MAP.size() - MAX_ENTRIES;
            for (int i = 0; i < drop; i++) MAP.remove(keys.get(i));
        }
        JSONObject o = new JSONObject();
        for (Map.Entry<String, Entry> me : MAP.entrySet()) {
            Entry e = me.getValue();
            try {
                o.put(me.getKey(), new JSONArray()
                        .put(e.ms).put(e.testedAt).put(e.okAt).put(e.fails));
            } catch (Exception ignored) {
            }
        }
        ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putString(KEY, o.toString()).apply();
        dirty = false;
    }

    public static synchronized void clear(Context ctx) {
        ensureLoaded(ctx);
        MAP.clear();
        dirty = true;
        flush(ctx);
    }

    /** 30 分钟内测过且可用。 */
    public static boolean aliveFresh(Entry e, long now) {
        return e != null && e.ms > 0 && now - e.testedAt <= FRESH_MS;
    }

    /** 30 分钟内测过且不可用。 */
    public static boolean deadFresh(Entry e, long now) {
        return e != null && e.ms <= 0 && e.testedAt > 0 && now - e.testedAt <= FRESH_MS;
    }

    /** 排序用：0 新鲜可用 / 1 没测过或已过期 / 2 新鲜不可用。 */
    public static int rank(Entry e, long now) {
        if (aliveFresh(e, now)) return 0;
        if (deadFresh(e, now)) return 2;
        return 1;
    }
}
