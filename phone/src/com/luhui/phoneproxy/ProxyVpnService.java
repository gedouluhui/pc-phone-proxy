package com.luhui.phoneproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import libv2ray.CoreCallbackHandler;
import libv2ray.CoreController;
import libv2ray.Libv2ray;

/**
 * 一键 VPN（v3.0）。
 *
 * <p>v3.0 的核心变化：**只把本机实测能连上的节点放进内核**。
 * <ol>
 *   <li>启动：30 分钟内实测可用的不足 6 个 → 先在本机网络实测整池（够 6 个就先连上）；</li>
 *   <li>一个都不可用 → 自动去公开源抓候选、实测、入池，再连；还是没有就明确报错、不建 VPN
 *       （以前会「已连接」但所有网页都打不开）；</li>
 *   <li>运行中：每 20 分钟后台复测，连续失败 3 次的导入节点删掉，可用不足 5 个自动补充，
 *       当前出口过半失效时自动重建内核。</li>
 * </ol>
 * 测速流量不走 VPN（App 自身 addDisallowedApplication），测的就是手机直连节点的真实情况。
 */
public class ProxyVpnService extends VpnService {

    public static final String ACTION_START = "com.luhui.phoneproxy.START";
    public static final String ACTION_STOP = "com.luhui.phoneproxy.STOP";
    public static final String ACTION_MEASURE = "com.luhui.phoneproxy.MEASURE";
    public static final String ACTION_GATE = "com.luhui.phoneproxy.GATE";
    public static final String EXTRA_NODE = "node"; // "auto" 或节点 tag
    public static final String EXTRA_FORCE = "force"; // true=即使选择未变也重启（导入新节点后生效）

    public static final int STATE_IDLE = 0;
    public static final int STATE_CONNECTING = 1;
    public static final int STATE_RUNNING = 2;

    /** UI 回调（单进程，静态引用即可）。 */
    public interface Listener {
        void onStateChanged(int state, String detail);
        void onLog(String line);
        void onTraffic(long upBps, long downBps, String activeTag);
        void onMeasure(String tag, long ms); // ms < 0 表示不可用
        void onNodesChanged();
        /** AI 闸门进度：done/total，ok 表示该节点通过了 ChatGPT+Claude 两个探针。 */
        void onGate(String tag, boolean ok, int done, int total);
    }

    public static volatile Listener listener;
    public static volatile int state = STATE_IDLE;
    public static volatile String runningNode = "";
    public static volatile String currentSelection = "auto";

    private static final String TAG = "PhoneProxy";
    private static final String CHANNEL = "vpn";

    /** 启动时至少要有这么多新鲜可用节点才跳过实测；实测时找到这么多就先连上。 */
    private static final int START_ENOUGH = 6;
    private static final long START_TEST_BUDGET_MS = 45000L;
    private static final long START_REFRESH_BUDGET_MS = 120000L;
    private static final long MEASURE_BUDGET_MS = 240000L;
    private static final long MAINT_FIRST_DELAY_MS = 3L * 60 * 1000;
    private static final long MAINT_INTERVAL_MS = 20L * 60 * 1000;
    private static final long MAINT_TEST_BUDGET_MS = 6L * 60 * 1000;
    private static final long MAINT_REFRESH_BUDGET_MS = 4L * 60 * 1000;
    private static final long RELOAD_MIN_GAP_MS = 8L * 60 * 1000;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    /** 一次闸门最多验证多少个节点。 */
    private static final int GATE_MAX = 24;
    private volatile boolean gating = false;
    private CoreController controller;
    private ParcelFileDescriptor tunFd;
    private volatile boolean starting = false;
    private ConnectivityManager.NetworkCallback netCallback;
    private volatile boolean trafficPolling = false;
    private Thread trafficThread;

    /** 每次 startMaintenance 自增；旧维护线程看到代号变化就退出。 */
    private final AtomicInteger maintGen = new AtomicInteger();
    private volatile long lastReloadAt = 0;
    /** 当前内核里的出口（Node.key），维护线程据此判断要不要重建。 */
    private final Set<String> memberKeys = Collections.synchronizedSet(new HashSet<String>());

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : ACTION_START;

        if (ACTION_STOP.equals(action)) {
            worker.submit(this::stopVpn);
            return START_NOT_STICKY;
        }
        if (ACTION_MEASURE.equals(action)) {
            if (state != STATE_RUNNING) startForegroundCompat();
            kickMeasureAll(state != STATE_RUNNING);
            return START_NOT_STICKY;
        }
        if (ACTION_GATE.equals(action)) {
            // 测节点不需要 VPN 在跑：measureOutboundDelay 自己起临时实例。
            if (state != STATE_RUNNING) startForegroundCompat();
            kickGate(state != STATE_RUNNING);
            return START_NOT_STICKY;
        }

        startForegroundCompat();
        String node = intent != null ? intent.getStringExtra(EXTRA_NODE) : "auto";
        final String sel = node == null || node.isEmpty() ? "auto" : node;
        final boolean force = intent != null && intent.getBooleanExtra(EXTRA_FORCE, false);

        if (starting) {
            log("正在启动中，请稍候…");
            return START_STICKY;
        }
        if (state == STATE_RUNNING && sel.equals(currentSelection) && !force) {
            log("已在运行中");
            return START_STICKY;
        }
        final boolean switching = state == STATE_RUNNING;
        starting = true;
        setState(STATE_CONNECTING, switching ? "正在切换节点…" : "正在连接…");
        worker.submit(() -> {
            if (switching) teardownCore(false);
            startVpn(sel);
        });
        return START_STICKY;
    }

    private void startVpn(String selection) {
        try {
            log("初始化内核 " + Libv2ray.checkVersionX());
            copyGeoAssets();
            Libv2ray.initCoreEnv(getFilesDir().getAbsolutePath(), "");

            List<ConfigBuilder.Node> nodes = ConfigBuilder.loadNodes(this);
            logPool(nodes);

            // 1) 只信本机实测。新鲜可用的不够就先测（够 START_ENOUGH 个就先连，其余后台测完）
            List<ConfigBuilder.Node> alive = NodePool.aliveFresh(this, nodes);
            if (alive.size() < START_ENOUGH && !nodes.isEmpty()) {
                setState(STATE_CONNECTING, "正在本机实测 " + nodes.size() + " 个节点…");
                log("在当前网络下实测节点（直连测，不经过代理）；找到 " + START_ENOUGH
                        + " 个可用就先连上，其余后台继续测…");
                NodeTester.run(this, nodes, START_TEST_BUDGET_MS, START_ENOUGH,
                        progress("实测"), this::notifyNodesChanged);
                alive = NodePool.aliveFresh(this, nodes);
                log("当前可用 " + alive.size() + " 个");
            }

            // 2) 一个都没有：自动去公开源补充
            if (alive.isEmpty()) {
                setState(STATE_CONNECTING, "现有节点都连不上，正在找新节点（1~3 分钟）…");
                log(nodes.isEmpty()
                        ? "节点池为空，自动从公开源抓取并实测…"
                        : "现有 " + nodes.size() + " 个节点在当前网络下都连不上，自动从公开源找新节点…");
                List<String> logs = new ArrayList<>();
                NodePool.refreshFromPublic(this, logs, START_REFRESH_BUDGET_MS, START_ENOUGH,
                        progress("新节点实测"), this::notifyNodesChanged);
                for (String l : logs) log("  · " + l);
                nodes = ConfigBuilder.loadNodes(this);
                alive = NodePool.aliveFresh(this, nodes);
                notifyNodesChanged();
            }

            // 3) 还是没有：不建 VPN。建了也只会「已连接但什么都打不开」，还断了用户的直连网络
            if (alive.isEmpty()) {
                throw new IllegalStateException("当前网络下没有找到能连上的节点。"
                        + "可以稍后重试、切换 Wi-Fi/流量，或导入自己的订阅");
            }

            List<ConfigBuilder.Node> members = NodePool.runtimeMembers(alive, nodes, selection);
            String fallback = "proxy-" + alive.get(0).tag;

            int gated = 0;
            for (ConfigBuilder.Node n : members) if (n.cg) gated++;
            if (gated == 0) {
                log("提示：AI 出口还没验证 → ChatGPT/Claude 可能 403。点「AI 闸门」验一次。");
            } else {
                log("AI 出口：" + gated + " 个已验证节点，AI 域名只走它们");
            }

            String config = ConfigBuilder.fullConfig(members, selection, fallback);
            tunFd = buildTun();
            if (tunFd == null) throw new IllegalStateException("VPN 建立失败（未授权？）");

            controller = newController();
            try {
                controller.startLoop(config, tunFd.getFd());
            } catch (Throwable startError) {
                // 内核是「整份配置要么全用、要么全不用」。错误原文必须先落地，不能吞掉。
                Log.e(TAG, "core rejected config", startError);
                log("内核拒绝了当前配置：" + startError.getMessage());
                new Thread(() -> {
                    int bad = ConfigBuilder.quarantineInvalidImports(getApplicationContext());
                    if (bad > 0) {
                        log("已标记 " + bad + " 个内核不兼容的导入节点，下次启动不再加载");
                    }
                }, "node-quarantine").start();

                // 不能拿同一个 tunFd 重试：libv2ray 失败清理时可能已经 close 过这个 fd。
                try { controller.stopLoop(); } catch (Throwable ignored) {}
                controller = null;
                closeTun();

                List<ConfigBuilder.Node> builtin = new ArrayList<>();
                for (ConfigBuilder.Node n : members) if (!n.imported) builtin.add(n);
                if (builtin.isEmpty() || builtin.size() == members.size()) throw startError;

                log("剔除 " + (members.size() - builtin.size()) + " 个导入节点，只用内置节点重试…");
                members = builtin;
                if (ConfigBuilder.find(members, selection) == null) selection = "auto";
                config = ConfigBuilder.fullConfig(members, selection, "proxy-" + members.get(0).tag);

                tunFd = buildTun();
                if (tunFd == null) throw new IllegalStateException("VPN 重建失败");
                controller = newController();
                controller.startLoop(config, tunFd.getFd());
            }
            if (!controller.getIsRunning()) throw new IllegalStateException("内核启动失败");

            currentSelection = selection;
            synchronized (memberKeys) {
                memberKeys.clear();
                for (ConfigBuilder.Node n : members) memberKeys.add(n.key);
            }
            ConfigBuilder.Node sel = ConfigBuilder.find(members, selection);
            if (sel != null && !sel.cg) {
                log("注意：固定节点 " + sel.name + " 没通过 AI 闸门，ChatGPT/Claude 可能 403");
            }
            if (sel != null && NodePool.msOf(this, sel) <= 0) {
                log("注意：固定节点 " + sel.name + " 最近实测不可用，打不开网页就切回「自动」");
            }
            runningNode = sel != null ? sel.name
                    : ("自动选线（" + members.size() + " 个可用节点）");
            registerUnderlyingNetwork();
            setState(STATE_RUNNING, "已连接 · " + runningNode);
            ConfigBuilder.Node best = alive.get(0);
            log("VPN 已启动，国内外自动分流"
                    + ("auto".equals(selection)
                    ? "；当前最快 " + best.name + " " + NodePool.msOf(this, best) + "ms"
                    : "，固定节点 " + runningNode));
            startTrafficPoll();
            startMaintenance();
        } catch (Throwable e) {
            Log.e(TAG, "start failed", e);
            log("启动失败：" + e.getMessage());
            failStop();
        } finally {
            starting = false;
        }
    }

    private void logPool(List<ConfigBuilder.Node> nodes) {
        int imported = 0;
        for (ConfigBuilder.Node n : nodes) if (n.imported) imported++;
        log("节点池：" + nodes.size() + " 个"
                + (imported > 0 ? "（内置 " + (nodes.size() - imported) + " + 导入 " + imported + "）" : ""));
        try {
            List<String> skips = new ArrayList<>(ConfigBuilder.lastSkips);
            if (!skips.isEmpty()) {
                StringBuilder sb = new StringBuilder("跳过 ").append(skips.size()).append(" 个：");
                int shown = 0;
                for (String s : skips) {
                    if (shown++ >= 4) {
                        sb.append(" …");
                        break;
                    }
                    sb.append(s).append("；");
                }
                log(sb.toString());
            }
        } catch (Throwable ignored) {
            // lastSkips 可能正被另一个线程的 loadNodes 改写，诊断日志丢一次无所谓
        }
    }

    private NodeTester.Callback progress(final String label) {
        return (n, ms, done, total) -> {
            Listener l = listener;
            if (l != null) l.onMeasure(n.tag, ms);
            if (done == total || done % 25 == 0) log(label + " " + done + "/" + total);
        };
    }

    private void notifyNodesChanged() {
        Listener l = listener;
        if (l != null) l.onNodesChanged();
    }

    // ------------------------------------------------------------ 后台维护

    private void startMaintenance() {
        final int gen = maintGen.incrementAndGet();
        Thread t = new Thread(() -> {
            long next = System.currentTimeMillis() + MAINT_FIRST_DELAY_MS;
            while (gen == maintGen.get()) {
                if (System.currentTimeMillis() < next) {
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        return;
                    }
                    continue;
                }
                try {
                    maintainOnce(gen);
                } catch (Throwable e) {
                    Log.w(TAG, "maintenance", e);
                }
                next = System.currentTimeMillis() + MAINT_INTERVAL_MS;
            }
        }, "pool-maint");
        t.setDaemon(true);
        t.start();
    }

    private void stopMaintenance() {
        maintGen.incrementAndGet();
    }

    private void maintainOnce(int gen) {
        if (state != STATE_RUNNING || NodeTester.busy()) return;
        List<ConfigBuilder.Node> nodes = ConfigBuilder.loadNodes(this);
        NodeTester.run(this, nodes, MAINT_TEST_BUDGET_MS, 0, null, null);
        if (gen != maintGen.get()) return;

        int pruned = NodePool.pruneDeadImports(this, NodeHealth.PRUNE_FAILS);
        if (pruned > 0) log("后台维护：清理 " + pruned + " 个连续失败的导入节点");
        NodePool.resort(this);
        nodes = ConfigBuilder.loadNodes(this);
        List<ConfigBuilder.Node> alive = NodePool.aliveFresh(this, nodes);

        if (alive.size() < NodePool.MIN_ALIVE_AUTOREFRESH && NodePool.refreshAllowed(this)) {
            log("后台维护：可用节点只剩 " + alive.size() + " 个，从公开源补充…");
            List<String> logs = new ArrayList<>();
            NodePool.refreshFromPublic(this, logs, MAINT_REFRESH_BUDGET_MS, 0, null,
                    this::notifyNodesChanged);
            for (String l : logs) log("  · " + l);
            nodes = ConfigBuilder.loadNodes(this);
            alive = NodePool.aliveFresh(this, nodes);
        }
        notifyNodesChanged();
        if (gen != maintGen.get() || state != STATE_RUNNING) return;

        Set<String> aliveKeys = new HashSet<>();
        for (ConfigBuilder.Node n : alive) aliveKeys.add(n.key);
        int live = 0;
        int dead = 0;
        synchronized (memberKeys) {
            for (String k : memberKeys) {
                if (aliveKeys.contains(k)) live++;
                else dead++;
            }
        }
        String why = null;
        if (live == 0 && !alive.isEmpty()) why = "当前出口全部失效";
        else if (dead > live && alive.size() > live) why = "过半出口失效";
        else if (live < 3 && alive.size() >= 3) why = "可用出口太少";
        log("后台维护：可用 " + alive.size() + " 个，当前出口 " + live + "/" + (live + dead) + " 可用");
        if (why != null && "auto".equals(currentSelection)) requestReload(why);
    }

    /** 用最新实测结果重建内核（短暂断流 1~2 秒）。只在维护线程判定需要时调用。 */
    private void requestReload(String why) {
        if (starting || state != STATE_RUNNING) return;
        long now = System.currentTimeMillis();
        if (now - lastReloadAt < RELOAD_MIN_GAP_MS) return;
        lastReloadAt = now;
        starting = true;
        log("节点池有变化（" + why + "），重建出口…");
        setState(STATE_CONNECTING, "正在更新节点…");
        final String sel = currentSelection;
        worker.submit(() -> {
            teardownCore(false);
            startVpn(sel);
        });
    }

    // ------------------------------------------------------------ 测速 / 闸门

    /** 整池实测（独立线程，结果通过 Listener.onMeasure 回传，写入 NodeHealth）。 */
    private void kickMeasureAll(final boolean stopWhenIdle) {
        new Thread(() -> {
            List<ConfigBuilder.Node> nodes = ConfigBuilder.loadNodes(this);
            if (nodes.isEmpty()) {
                log("节点池为空：点「启动代理」会自动从公开源找节点，或先导入订阅");
                if (stopWhenIdle && state != STATE_RUNNING) stopIdleMeasure();
                return;
            }
            log("开始实测（" + nodes.size() + " 个节点，手机直连测，不经过代理）…");
            Map<String, Long> res = NodeTester.run(this, nodes, MEASURE_BUDGET_MS, 0,
                    progress("实测"), null);
            int ok = 0;
            for (Long v : res.values()) if (v != null && v > 0) ok++;
            log("实测完成：可用 " + ok + "/" + nodes.size()
                    + (ok == 0 ? "。都连不上：点「导入节点 / 订阅 → 从公开源导入」找新节点" : ""));
            NodePool.resort(this);
            notifyNodesChanged();
            if (stopWhenIdle && state != STATE_RUNNING) stopIdleMeasure();
        }, "measure-all").start();
    }

    /**
     * AI 出口闸门：对实测最快的 GATE_MAX 个节点各跑 chatgpt.com / claude.ai 两个探针。
     * libv2ray 的 measureInstDelay 只把 200/204 当成功，地区封锁是 403 → 返回 -1。
     */
    private void kickGate(final boolean stopWhenIdle) {
        if (gating) {
            log("AI 闸门已经在跑了，等它出结果…");
            return;
        }
        gating = true;
        new Thread(() -> {
            try {
                List<ConfigBuilder.Node> nodes = ConfigBuilder.loadNodes(this);
                if (nodes.isEmpty()) {
                    log("没有节点可验证");
                    return;
                }
                // 只验本机实测能连上的；还没测过就按原顺序
                List<ConfigBuilder.Node> cand = NodePool.aliveFresh(this, nodes);
                if (cand.isEmpty()) cand = NodePool.sortedForDisplay(this, nodes);
                final int total = Math.min(cand.size(), GATE_MAX);
                log("AI 出口验证：" + total + "/" + nodes.size() + " 个节点 × "
                        + ConfigBuilder.AI_PROBES.length + " 个探针（ChatGPT / Claude）…");
                final AtomicInteger done = new AtomicInteger();
                final AtomicInteger ok = new AtomicInteger();
                ExecutorService pool = Executors.newFixedThreadPool(4);
                for (int i = 0; i < total; i++) {
                    final ConfigBuilder.Node n = cand.get(i);
                    pool.submit(() -> {
                        boolean pass = probeAiGate(n);
                        try {
                            ConfigBuilder.saveGate(this, n.key, pass);
                        } catch (Throwable ignored) {
                        }
                        int d = done.incrementAndGet();
                        if (pass) ok.incrementAndGet();
                        Listener l = listener;
                        if (l != null) l.onGate(n.tag, pass, d, total);
                        if (d == total) {
                            log("AI 出口验证完成：合格 " + ok.get() + "/" + total
                                    + (ok.get() == 0
                                    ? "。这批节点都过不了地区闸门，换节点源或换网络再试"
                                    : "。ChatGPT/Claude 只会走这些节点（重连后生效）"));
                        }
                    });
                }
                pool.shutdown();
                pool.awaitTermination(15, java.util.concurrent.TimeUnit.MINUTES);
            } catch (Throwable e) {
                log("AI 闸门失败：" + e.getMessage());
            } finally {
                gating = false;
                if (stopWhenIdle && state != STATE_RUNNING) stopIdleMeasure();
            }
        }, "ai-gate").start();
    }

    /** 两个探针都返回 >0 才算过（libv2ray 只把 200/204 认作成功）。 */
    private static boolean probeAiGate(ConfigBuilder.Node n) {
        String cfg;
        try {
            cfg = ConfigBuilder.measureConfig(n);
        } catch (Throwable t) {
            return false;
        }
        for (String url : ConfigBuilder.AI_PROBES) {
            try {
                if (Libv2ray.measureOutboundDelay(cfg, url) <= 0) return false;
            } catch (Throwable t) {
                return false;
            }
        }
        return true;
    }

    private void stopIdleMeasure() {
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    // ------------------------------------------------------------ 流量统计

    private void startTrafficPoll() {
        stopTrafficPoll();
        trafficPolling = true;
        trafficThread = new Thread(() -> {
            long prevT = System.currentTimeMillis();
            while (trafficPolling) {
                String raw = null;
                CoreController c = controller;
                try {
                    if (c != null) raw = c.queryAllOutboundTrafficStats();
                } catch (Throwable ignored) {}
                long now = System.currentTimeMillis();
                double dt = Math.max(0.5, (now - prevT) / 1000.0);
                prevT = now;

                long up = 0, down = 0, activeMax = 0;
                String active = "";
                if (raw != null && !raw.isEmpty()) {
                    for (String part : raw.split(";")) {
                        part = part.trim();
                        if (part.isEmpty()) continue;
                        String[] f = part.split(",");
                        if (f.length < 3) continue;
                        String tag = f[0].trim();
                        // 自动模式的实际流量记在 balancer / cg-balancer 上，
                        // 固定模式记在 proxy-<tag> 上，两者都要算进来。
                        boolean counted = tag.startsWith("proxy-") || tag.startsWith("cg-")
                                || "balancer".equals(tag) || "cg-balancer".equals(tag);
                        if (!counted) continue;
                        long v;
                        try {
                            v = Long.parseLong(f[2].trim());
                        } catch (Exception e) {
                            continue;
                        }
                        boolean isUp = "uplink".equalsIgnoreCase(f[1].trim());
                        if (isUp) up += v; else down += v;
                        if (v > activeMax) {
                            activeMax = v;
                            active = tag.startsWith("proxy-") ? tag.substring(6)
                                    : tag.startsWith("cg-") ? tag.substring(3) : tag;
                        }
                    }
                }
                Listener l = listener;
                if (l != null && trafficPolling) {
                    l.onTraffic((long) (up / dt), (long) (down / dt), active);
                }
                try {
                    Thread.sleep(1500);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "traffic-poll");
        trafficThread.setDaemon(true);
        trafficThread.start();
    }

    private void stopTrafficPoll() {
        trafficPolling = false;
        Thread t = trafficThread;
        trafficThread = null;
        if (t != null) {
            try { t.join(300); } catch (InterruptedException ignored) {}
        }
    }

    // ------------------------------------------------------------ 启停

    private void stopVpn() {
        stopMaintenance();
        teardownCore(true);
        setState(STATE_IDLE, "未连接");
        log("已断开");
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    /** 停内核/关 TUN/停统计；notifyState=false 用于切换节点时避免闪“未连接”。 */
    private void teardownCore(boolean notifyState) {
        stopTrafficPoll();
        try {
            if (controller != null) {
                controller.stopLoop();
                controller = null;
            }
        } catch (Throwable e) {
            Log.w(TAG, "stopLoop", e);
        }
        closeTun();
        if (notifyState) {
            runningNode = "";
        }
    }

    /** VPN 网卡：双栈都接管，否则 IPv6 流量会绕过隧道泄漏真实地址。 */
    private ParcelFileDescriptor buildTun() throws Exception {
        return new Builder()
                .setSession("手机代理")
                .addAddress("172.19.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addAddress("fd00::1", 126)
                .addRoute("::", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setMtu(1500)
                .addDisallowedApplication(getPackageName())  // 内核出站与测速绕过 TUN，防回环
                .establish();
    }

    private CoreController newController() {
        return Libv2ray.newCoreController(new CoreCallbackHandler() {
            @Override public long startup() { return 0; }
            @Override public long shutdown() { return 0; }
            @Override public long onEmitStatus(long code, String msg) {
                Log.i(TAG, "core status " + code + ": " + msg);
                return 0;
            }
        });
    }

    private void failStop() {
        stopMaintenance();
        teardownCore(true);
        setState(STATE_IDLE, "启动失败");
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void closeTun() {
        if (tunFd != null) {
            try { tunFd.close(); } catch (Exception ignored) {}
            tunFd = null;
        }
    }

    private void copyGeoAssets() throws Exception {
        for (String name : new String[]{"geoip.dat", "geosite.dat"}) {
            File dst = new File(getFilesDir(), name);
            InputStream in = getAssets().open(name);
            if (dst.exists() && dst.length() == in.available()) { in.close(); continue; }
            FileOutputStream out = new FileOutputStream(dst);
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            out.close();
            in.close();
        }
    }

    private void startForegroundCompat() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "代理状态",
                    NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Intent pi = new Intent(this, MainActivity.class);
        PendingIntent flags = PendingIntent.getActivity(this, 0, pi,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL)
                : new Notification.Builder(this);
        Notification n = b.setContentTitle("手机代理运行中")
                .setContentText("国内外自动分流 · 点击打开")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(flags)
                .setOngoing(true)
                .build();
        startForeground(1, n);
    }

    private void setState(int s, String detail) {
        state = s;
        Listener l = listener;
        if (l != null) l.onStateChanged(s, detail);
    }

    private void log(String line) {
        Log.i(TAG, line);
        Listener l = listener;
        if (l != null) l.onLog(line);
    }

    @Override
    public void onDestroy() {
        stopMaintenance();
        unregisterUnderlyingNetwork();
        stopTrafficPoll();
        worker.submit(() -> {
            try { if (controller != null) controller.stopLoop(); } catch (Throwable ignored) {}
            closeTun();
            state = STATE_IDLE;
            runningNode = "";
        });
        worker.shutdown();
        super.onDestroy();
    }

    /**
     * 把真实的物理网络告诉系统。不做这件事时，Android 9+ 无法判断 VPN 下面
     * 是 Wi-Fi 还是计费网络，切换网络（Wi-Fi ↔ 蜂窝）后也容易把连接挂在旧网卡上。
     * 过滤器里排除 VPN 自身，否则会把自己的网卡当成底层网络。
     * v3.0：重建内核会再次调用，已注册时直接返回，避免重复注册回调。
     */
    private void registerUnderlyingNetwork() {
        if (netCallback != null) return;
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return;
            NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build();
            netCallback = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { applyUnderlying(network); }
                @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities caps) {
                    applyUnderlying(network);
                }
            };
            cm.registerNetworkCallback(request, netCallback);
        } catch (Throwable e) {
            netCallback = null;
            Log.w(TAG, "registerNetworkCallback failed", e);
        }
    }

    private void applyUnderlying(Network network) {
        if (network == null) return;
        try {
            setUnderlyingNetworks(new Network[]{network});
        } catch (Throwable ignored) {}
    }

    private void unregisterUnderlyingNetwork() {
        if (netCallback == null) return;
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm != null) cm.unregisterNetworkCallback(netCallback);
        } catch (Throwable ignored) {}
        netCallback = null;
    }

    @Override
    public void onRevoke() {
        log("VPN 授权被系统收回，正在清理内核与网卡");
        // onRevoke 不保证在主线程；拆除工作统一丢给 worker，避免与启动流程并发。
        worker.submit(this::stopVpn);
    }
}
