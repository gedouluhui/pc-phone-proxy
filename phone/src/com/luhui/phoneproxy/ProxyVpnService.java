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
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
    }

    public static volatile Listener listener;
    public static volatile int state = STATE_IDLE;
    public static volatile String runningNode = "";
    public static volatile String currentSelection = "auto";

    private static final String TAG = "PhoneProxy";
    private static final String CHANNEL = "vpn";

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService measurePool = Executors.newFixedThreadPool(4);
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

            Builder builder = new Builder()
                    .setSession("手机代理")
                    .addAddress("172.19.0.1", 30)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("1.1.1.1")
                    .setMtu(1500)
                    .addDisallowedApplication(getPackageName()); // 内核出站绕过 TUN，防回环
            tunFd = builder.establish();
            if (tunFd == null) throw new IllegalStateException("VPN 建立失败（未授权？）");

            controller = Libv2ray.newCoreController(new CoreCallbackHandler() {
                @Override public long startup() { return 0; }
                @Override public long shutdown() { return 0; }
                @Override public long onEmitStatus(long code, String msg) {
                    Log.i(TAG, "core status " + code + ": " + msg);
                    return 0;
                }
            });
            controller.startLoop(config, tunFd.getFd());
            if (!controller.getIsRunning()) throw new IllegalStateException("内核启动失败");

            currentSelection = selection;
            ConfigBuilder.Node sel = ConfigBuilder.find(nodes, selection);
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
