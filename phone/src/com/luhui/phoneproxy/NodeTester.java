package com.luhui.phoneproxy;

import android.content.Context;

import org.json.JSONObject;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import libv2ray.Libv2ray;

/**
 * 在用户自己的网络下实测节点（v3.0 新增）。
 *
 * <p>两段式：
 * <ol>
 *   <li>TCP 直连预筛：GFW 封 IP 时 SYN 直接没回应，3 秒判死，32 并发，几百个节点半分钟筛完；</li>
 *   <li>内核实测：对预筛通过的节点用 {@code Libv2ray.measureOutboundDelay} 真发一次
 *       HTTPS 请求（只认 200/204），能区分「端口开着」和「协议真能用」。</li>
 * </ol>
 *
 * <p>App 自身在 VPN 建立时已 {@code addDisallowedApplication}，所以这里的流量永远直连，
 * 测的是「手机直连节点」——和真实使用时内核拨号的路径一致，VPN 开着测也不会被自己代理。
 *
 * <p>{@code enough>0} 时，拿到这么多可用节点就提前返回（启动时用：先连上，再说），
 * 剩下的继续在后台测完、写进 {@link NodeHealth}，测完调用 {@code onAllDone}。
 */
public final class NodeTester {

    public interface Callback {
        void onResult(ConfigBuilder.Node node, long ms, int done, int total);
    }

    /** 走代理出口访问；在境外出口上 204 极小、几乎不耗流量。 */
    public static final String PROBE_URL = "https://www.gstatic.com/generate_204";

    private static final int TCP_TIMEOUT_MS = 3000;
    private static final int TCP_THREADS = 32;
    // v3.2：12（Hysteria2 节点跳过 TCP 预筛，死节点会占住内核线程到超时）
    private static final int CORE_THREADS = 12;

    private static final AtomicInteger RUNNING = new AtomicInteger();

    private NodeTester() {
    }

    /** 有实测在跑（后台维护据此跳过本轮，避免叠加）。 */
    public static boolean busy() {
        return RUNNING.get() > 0;
    }

    /**
     * @param budgetMs 最多阻塞这么久；到点就返回已有结果，剩余的在后台继续
     * @param enough   &gt;0：可用数达到这个值就提前返回
     * @return tag -&gt; ms（&lt;=0 不可用），只含返回前已测完的节点
     */
    public static Map<String, Long> run(Context ctx, final List<ConfigBuilder.Node> nodes,
                                        long budgetMs, final int enough,
                                        final Callback cb, final Runnable onAllDone) {
        final Context app = ctx.getApplicationContext();
        final Map<String, Long> results = new ConcurrentHashMap<>();
        if (nodes == null || nodes.isEmpty()) {
            if (onAllDone != null) {
                try {
                    onAllDone.run();
                } catch (Throwable ignored) {
                }
            }
            return results;
        }
        try {
            Libv2ray.initCoreEnv(app.getFilesDir().getAbsolutePath(), "");
        } catch (Throwable ignored) {
        }
        RUNNING.incrementAndGet();
        final int total = nodes.size();
        final AtomicInteger done = new AtomicInteger();
        final AtomicInteger alive = new AtomicInteger();
        final ExecutorService tcpPool = Executors.newFixedThreadPool(Math.min(TCP_THREADS, total));
        final ExecutorService corePool = Executors.newFixedThreadPool(Math.min(CORE_THREADS, total));

        for (final ConfigBuilder.Node n : nodes) {
            try {
                tcpPool.execute(() -> {
                    final long tcp = tcpProbe(n);
                    if (tcp < 0) {
                        finish(app, n, -1, results, done, alive, total, cb);
                        return;
                    }
                    try {
                        corePool.execute(() -> {
                            long ms = coreProbe(n.outbound);
                            // v3.1：TCP 能连上、TLS 却不通，多半是 SNI 被封。拆分 ClientHello 再试一次，
                            // 通了就记下来，之后这个节点一律带分片（ConfigBuilder.loadNodes 负责套上）。
                            if (ms <= 0 && tcp > 0 && NodeConfigCodec.canFragment(n.outbound)
                                    && !NodeConfigCodec.hasFragment(n.outbound)) {
                                try {
                                    long m2 = coreProbe(NodeConfigCodec.withTlsFragment(n.outbound));
                                    if (m2 > 0) {
                                        NodeHealth.setFrag(app, n.key, true);
                                        ms = m2;
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                            finish(app, n, ms, results, done, alive, total, cb);
                        });
                    } catch (RejectedExecutionException e) {
                        finish(app, n, -1, results, done, alive, total, cb);
                    }
                });
            } catch (RejectedExecutionException e) {
                finish(app, n, -1, results, done, alive, total, cb);
            }
        }
        // 已提交的任务照常执行；corePool 要等 TCP 阶段全部结束才能关，否则后续提交会被拒
        tcpPool.shutdown();

        Thread reaper = new Thread(() -> {
            try {
                tcpPool.awaitTermination(10, TimeUnit.MINUTES);
            } catch (InterruptedException ignored) {
            }
            corePool.shutdown();
            try {
                corePool.awaitTermination(15, TimeUnit.MINUTES);
            } catch (InterruptedException ignored) {
            }
            NodeHealth.flush(app);
            RUNNING.decrementAndGet();
            if (onAllDone != null) {
                try {
                    onAllDone.run();
                } catch (Throwable ignored) {
                }
            }
        }, "node-test-reaper");
        reaper.setDaemon(true);
        reaper.start();

        long deadline = System.currentTimeMillis() + Math.max(1000L, budgetMs);
        while (System.currentTimeMillis() < deadline) {
            if (done.get() >= total) break;
            if (enough > 0 && alive.get() >= enough) break;
            try {
                Thread.sleep(250);
            } catch (InterruptedException e) {
                break;
            }
        }
        NodeHealth.flush(app);
        return new HashMap<>(results);
    }

    private static void finish(Context app, ConfigBuilder.Node n, long ms,
                               Map<String, Long> results, AtomicInteger done,
                               AtomicInteger alive, int total, Callback cb) {
        long v = ms > 0 ? ms : -1;
        results.put(n.tag, v);
        NodeHealth.record(app, n.key, v);
        if (v > 0) alive.incrementAndGet();
        int d = done.incrementAndGet();
        if (d % 40 == 0) NodeHealth.flush(app);
        if (cb != null) {
            try {
                cb.onResult(n, v, d, total);
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * TCP 直连预筛。返回 &gt;0 = 连上用时；0 = 无法预筛（UDP 传输/地址未知），交给内核测；
     * &lt;0 = 连不上。
     */
    static long tcpProbe(ConfigBuilder.Node n) {
        String[] ep = ConfigBuilder.endpoint(n.outbound);
        if (ep == null || isUdpTransport(n.outbound)) return 0;
        int port;
        try {
            port = Integer.parseInt(ep[1]);
        } catch (NumberFormatException e) {
            return 0;
        }
        Socket s = new Socket();
        long t0 = System.nanoTime();
        try {
            s.connect(new InetSocketAddress(ep[0], port), TCP_TIMEOUT_MS);
            return Math.max(1L, (System.nanoTime() - t0) / 1000000L);
        } catch (Throwable e) {
            return -1;
        } finally {
            try {
                s.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /** 内核真实请求一次；只认 200/204（libv2ray measureInstDelay 的规则）。 */
    static long coreProbe(JSONObject outbound) {
        return coreFetch(outbound, PROBE_URL);
    }

    private static long coreFetch(JSONObject outbound, String url) {
        try {
            long ms = Libv2ray.measureOutboundDelay(ConfigBuilder.measureConfigOf(outbound), url);
            return ms > 0 ? ms : -1;
        } catch (Throwable t) {
            return -1;
        }
    }

    /** KCP 与 Hysteria（QUIC）走 UDP，TCP 预筛没有意义，直接交给内核测。 */
    private static boolean isUdpTransport(JSONObject ob) {
        if (ob == null) return false;
        if ("hysteria".equalsIgnoreCase(ob.optString("protocol", ""))) return true;
        JSONObject st = ob.optJSONObject("streamSettings");
        String net = st == null ? "" : st.optString("network", "");
        return "kcp".equalsIgnoreCase(net) || "mkcp".equalsIgnoreCase(net)
                || "hysteria".equalsIgnoreCase(net);
    }

    // ------------------------------------------------------------ 带宽实测（v3.1）

    private static final String SPEED_URL = "https://speed.cloudflare.com/__down?bytes=";

    /**
     * 对给定节点实测下行带宽，结果写入 {@link NodeHealth#recordSpeed}。阻塞调用，2 并发。
     *
     * <p>libv2ray 的 measureInstDelay 会把响应体读完再计时、取两次里较快的一次（第二次复用连接），
     * 所以「下载耗时 − 204 延迟」≈ 纯传输时间，bytes/传输时间就是可用带宽。
     * 计费网络（移动数据）只下 128 KB，Wi-Fi 下 256 KB。下载失败不判节点死，只记成很慢。
     */
    public static int speedTest(Context ctx, List<ConfigBuilder.Node> nodes, boolean metered) {
        if (nodes == null || nodes.isEmpty()) return 0;
        final Context app = ctx.getApplicationContext();
        final int bytes = metered ? 131072 : 262144;
        final AtomicInteger ok = new AtomicInteger();
        RUNNING.incrementAndGet();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (final ConfigBuilder.Node n : nodes) {
                pool.execute(() -> {
                    NodeHealth.Entry e = NodeHealth.get(app, n.key);
                    long base = e != null && e.ms > 0 ? e.ms : 0;
                    long ms = coreFetch(n.outbound, SPEED_URL + bytes);
                    long kbps;
                    if (ms <= 0) {
                        kbps = 8; // 12 秒内没下完：当作极慢，排到后面
                    } else {
                        long transfer = ms - base;
                        if (transfer < 60) transfer = Math.max(60, ms / 2);
                        kbps = Math.max(1, (bytes / 1024L) * 1000L / transfer);
                        ok.incrementAndGet();
                    }
                    NodeHealth.recordSpeed(app, n.key, kbps);
                });
            }
            pool.shutdown();
            pool.awaitTermination(5, TimeUnit.MINUTES);
        } catch (Throwable ignored) {
        } finally {
            pool.shutdownNow();
            NodeHealth.flush(app);
            RUNNING.decrementAndGet();
        }
        return ok.get();
    }
}
