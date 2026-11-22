package com.luhui.phoneproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import libv2ray.CoreCallbackHandler;
import libv2ray.CoreController;
import libv2ray.Libv2ray;

/**
 * 一键 VPN（v2）：全部节点进 Xray，auto 模式用 observatory+balancer 持续自动选线，
 * 连接中不阻塞（秒连），坏节点由内核自动跳过；支持运行中切换节点、导入节点、
 * 逐节点测速与实时流量统计。
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

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService measurePool = Executors.newFixedThreadPool(4);
    /** tag -> 上次实测延迟（ms）。闸门只验证最快的那些，避免 120 个节点跑十几分钟。 */
    private final Map<String, Long> delayMs = new ConcurrentHashMap<>();
    /** 一次闸门最多验证多少个节点。 */
    private static final int GATE_MAX = 24;
    private volatile boolean gating = false;
    private CoreController controller;
    private ParcelFileDescriptor tunFd;
    private volatile boolean starting = false;
    private volatile boolean trafficPolling = false;
    private Thread trafficThread;

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
        boolean switching = state == STATE_RUNNING;
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
            if (nodes.isEmpty()) throw new IllegalStateException("没有可用节点");
            int imported = 0;
            for (ConfigBuilder.Node n : nodes) if (n.imported) imported++;
            log("节点池：" + nodes.size() + " 个"
                    + (imported > 0 ? "（内置 " + (nodes.size() - imported) + " + 导入 " + imported + "）" : ""));
            if (!ConfigBuilder.lastSkips.isEmpty()) {
                StringBuilder sb = new StringBuilder("跳过 ")
                        .append(ConfigBuilder.lastSkips.size()).append(" 个：");
                int shown = 0;
                for (String s : ConfigBuilder.lastSkips) {
                    if (shown++ >= 4) { sb.append(" …"); break; }
                    sb.append(s).append("；");
                }
                log(sb.toString());
            }

            String config = ConfigBuilder.fullConfig(nodes, selection);

            int gated = 0;
            for (ConfigBuilder.Node n : nodes) if (n.cg) gated++;
            if (gated == 0) {
                // 静默降级是最坑的：用户只会看到 ChatGPT 403，却不知道是出口没验证
                log("提示：AI 出口还没验证 → ChatGPT/Claude 可能 403。点「AI 闸门」验一次。");
            } else {
                log("AI 出口：" + gated + " 个已验证节点，AI 域名只走它们");
            }

            tunFd = buildTun();
            if (tunFd == null) throw new IllegalStateException("VPN 建立失败（未授权？）");

            controller = newController();
            try {
                controller.startLoop(config, tunFd.getFd());
            } catch (Throwable startError) {
                // 内核是「整份配置要么全用、要么全不用」。真正的原因是某条出站不合法，
                // 但错误原文必须先落地，不能吞掉（之前重试成功就再也查不到根因了）。
                Log.e(TAG, "core rejected config", startError);
                log("内核拒绝了当前配置：" + startError.getMessage());

                // 不能拿同一个 tunFd 重试：libv2ray 失败清理时可能已经 close 过这个 fd，
                // 复用会拿到 EBADF 或者一个被复用的句柄。先停内核、关网卡、再重建。
                try { controller.stopLoop(); } catch (Throwable ignored) {}
                controller = null;
                closeTun();

                java.util.List<ConfigBuilder.Node> builtin = new java.util.ArrayList<>();
                for (ConfigBuilder.Node n : nodes) if (!n.imported) builtin.add(n);
                if (builtin.isEmpty() || builtin.size() == nodes.size()) throw startError;

                log("剔除 " + (nodes.size() - builtin.size()) + " 个导入节点，只用内置节点重试…");
                nodes = builtin;                       // 必须同步，否则下面 UI 会显示成已剔除的节点
                if (ConfigBuilder.find(nodes, selection) == null) selection = "auto";
                config = ConfigBuilder.fullConfig(nodes, selection);

                tunFd = buildTun();
                if (tunFd == null) throw new IllegalStateException("VPN 重建失败");
                controller = newController();
                controller.startLoop(config, tunFd.getFd());
            }
            if (!controller.getIsRunning()) throw new IllegalStateException("内核启动失败");

            currentSelection = selection;
            ConfigBuilder.Node sel = ConfigBuilder.find(nodes, selection);
            if (sel != null && !sel.cg) {
                log("注意：固定节点 " + sel.name + " 没通过 AI 闸门，ChatGPT/Claude 可能 403");
            }
            runningNode = sel != null ? sel.name
                    : ("自动选线（" + nodes.size() + " 节点池）");
            setState(STATE_RUNNING, "已连接 · " + runningNode);
            log("VPN 已启动，国内外自动分流"
                    + ("auto".equals(selection) ? "，自动选线已启用" : "，固定节点 " + runningNode));
            startTrafficPoll();
            kickMeasureAll(false); // 后台填充各节点延迟，供 UI 显示
        } catch (Throwable e) {
            Log.e(TAG, "start failed", e);
            log("启动失败：" + e.getMessage());
            failStop();
        } finally {
            starting = false;
        }
    }

    /** 逐节点测速（独立线程，结果通过 Listener.onMeasure 回传）。 */
    private void kickMeasureAll(boolean stopWhenIdle) {
        new Thread(() -> {
            List<ConfigBuilder.Node> nodes = ConfigBuilder.loadNodes(this);
            if (nodes.isEmpty()) {
                if (stopWhenIdle) stopIdleMeasure();
                return;
            }
            log("开始测速（" + nodes.size() + " 个节点）…");
            final java.util.concurrent.CountDownLatch latch =
                    new java.util.concurrent.CountDownLatch(nodes.size());
            for (ConfigBuilder.Node n : nodes) {
                measurePool.submit(() -> {
                    long ms = -1;
                    try {
                        ms = Libv2ray.measureOutboundDelay(ConfigBuilder.measureConfig(n), "");
                        if (ms > 0) delayMs.put(n.tag, ms); else delayMs.remove(n.tag);
                    } catch (Throwable ignored) {
                    } finally {
                        latch.countDown();
                    }
                    Listener l = listener;
                    if (l != null) l.onMeasure(n.tag, ms);
                });
            }
            try {
                latch.await(180, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
            if (stopWhenIdle && state != STATE_RUNNING) stopIdleMeasure();
        }, "measure-all").start();
    }

    /**
     * AI 出口闸门：对最快的 GATE_MAX 个节点各跑 chatgpt.com / claude.ai 两个探针。
     *
     * 为什么必须在手机上实测，而不是照搬电脑端的深测结果：用户多半用「公开源导入」，
     * 那批节点在 App 里没有 cg 标记，AI 域名只能落回普通 balancer，等于交给一个
     * 可能被 Cloudflare 判「不支持地区」的出口——现象就是 ChatGPT/Claude 打开 403。
     * libv2ray 的 measureInstDelay 只把 200/204 当成功，地区封锁是 403 → 返回 -1，
     * 所以两个探针能真实区分「能过闸门」和「只是延迟低」。
     */
    private void kickGate(boolean stopWhenIdle) {
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
                // 先验最快的那些：慢节点本来也抢不到流量，没必要为它们花时间
                List<ConfigBuilder.Node> cand = new ArrayList<>(nodes);
                cand.sort((a, b) -> Long.compare(
                        delayMs.containsKey(a.tag) ? delayMs.get(a.tag) : Long.MAX_VALUE / 2,
                        delayMs.containsKey(b.tag) ? delayMs.get(b.tag) : Long.MAX_VALUE / 2));
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
                                    : "。ChatGPT/Claude 只会走这些节点"));
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

    private void stopVpn() {
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
                .addDisallowedApplication(getPackageName())  // 内核出站绕过 TUN，防回环
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
        stopTrafficPoll();
        worker.submit(() -> {
            try { if (controller != null) controller.stopLoop(); } catch (Throwable ignored) {}
            closeTun();
            state = STATE_IDLE;
            runningNode = "";
        });
        worker.shutdown();
        measurePool.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        log("VPN 授权被系统收回");
        worker.submit(this::stopVpn);
    }
}
