package com.luhui.phoneproxy;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** JVM proof for cancellation, session invalidation, debounce and recovery policy. */
public final class LifecyclePoc {
    private static int passed;
    private static int failed;

    private static void check(String name, boolean condition, String detail) {
        if (condition) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + " " + detail);
        }
    }

    public static void main(String[] args) throws Exception {
        LifecycleState lifecycle = new LifecycleState();
        LifecycleState.Session first = lifecycle.begin();
        check("new session current", lifecycle.isCurrent(first), "not current");
        int stopped = lifecycle.stop();
        check("stop invalidates session", stopped != first.id && !lifecycle.isCurrent(first),
                "stale session current");
        LifecycleState.Session second = lifecycle.begin();
        check("new session does not revive old", lifecycle.isCurrent(second)
                && !lifecycle.isCurrent(first) && first.control.isCancelled(), "old session revived");
        int beforeReload = lifecycle.currentId();
        LifecycleState.Session reload = lifecycle.begin(beforeReload);
        check("reload can supersede current generation", reload != null
                && lifecycle.isCurrent(reload), "reload rejected");
        lifecycle.stop();
        check("reload cannot supersede STOP", lifecycle.begin(beforeReload + 1) == null,
                "stale reload revived STOP");

        TaskControl control = new TaskControl();
        ExecutorService pool = Executors.newSingleThreadExecutor();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch exited = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        pool.execute(() -> {
            started.countDown();
            try { new CountDownLatch(1).await(); }
            catch (InterruptedException expected) { interrupted.set(true); }
            finally { exited.countDown(); }
        });
        started.await(2, TimeUnit.SECONDS);
        control.cancel();
        boolean terminated = TaskControl.shutdownAndAwait(control, 2000, pool);
        check("cancel interrupts and reaps executor", terminated && interrupted.get()
                && exited.getCount() == 0, "executor still running");

        AtomicBoolean callback = new AtomicBoolean();
        if (terminated && !control.isCancelled()) callback.set(true);
        check("cancelled task cannot emit completion", !callback.get(), "completion emitted");

        ExecutorService stubbornPool = Executors.newSingleThreadExecutor();
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean stubbornExited = new AtomicBoolean();
        stubbornPool.execute(() -> {
            while (release.getCount() != 0) {
                try { release.await(); }
                catch (InterruptedException expected) { }
            }
            stubbornExited.set(true);
        });
        TaskControl stubbornControl = new TaskControl();
        stubbornControl.cancel();
        boolean stubbornTerminated = TaskControl.shutdownAndAwait(stubbornControl, 50, stubbornPool);
        check("uncooperative worker is not reported terminated", !stubbornTerminated
                && !stubbornExited.get(), "false completion");
        release.countDown();
        stubbornPool.awaitTermination(2, TimeUnit.SECONDS);

        NetworkDebouncer network = new NetworkDebouncer();
        check("first network applies without rebuild", "wifi".equals(network.applied("wifi", 0))
                && network.due(0) == null, "unexpected rebuild");
        network.onChange("wifi", 100);
        check("same network does not arm rebuild", network.due(5000) == null, "duplicate rebuild");
        network.onChange("cell", 1000);
        check("network change is debounced", network.due(2000) == null, "fired too early");
        check("network change fires once", "cell".equals(network.due(3000))
                && network.due(4000) == null, "missing or duplicate rebuild");
        network.onChange(null, 5000);
        network.onChange("wifi", 5100);
        check("loss followed by return resets debounce", network.due(6000) == null
                && "wifi".equals(network.due(7000)), "loss debounce not reset");
        network.onChange(null, 8000);
        network.onChange("wifi", 8100);
        check("same network return clears pending loss", network.due(9000) == null
                && "wifi".equals(network.due(10000)), "pending loss not cleared");

        CoreRecoveryPolicy recovery = new CoreRecoveryPolicy();
        check("dead core recovers first time", recovery.onPoll(false, 0), "no recovery");
        check("dead core backs off", !recovery.onPoll(false, 1000), "no backoff");
        check("dead core retries after backoff", recovery.onPoll(false, 6000), "retry missing");
        check("dead core retries third time", recovery.onPoll(false, 16000), "third retry missing");
        check("automatic recovery is bounded", !recovery.onPoll(false, 26000)
                && !recovery.onPoll(false, 600000), "unbounded recovery");
        recovery.onPoll(true, 600001);
        check("healthy core resets budget", recovery.onPoll(false, 600002), "budget not reset");

        System.out.println("{\"cases\":" + (passed + failed) + ",\"passed\":" + passed
                + ",\"failed\":" + failed + "}");
        if (failed > 0) System.exit(1);
    }
}
