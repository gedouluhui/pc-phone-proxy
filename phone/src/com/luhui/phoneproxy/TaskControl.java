package com.luhui.phoneproxy;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/** Cooperative cancellation plus executor reaping with a hard wall-clock bound. */
public final class TaskControl implements Cancellation {
    private volatile boolean cancelled;

    public void cancel() {
        cancelled = true;
    }

    @Override public boolean isCancelled() {
        return cancelled;
    }

    /** Returns true only when every pool has actually terminated. */
    public static boolean shutdownAndAwait(Cancellation cancellation, long timeoutMs,
                                           ExecutorService... pools) {
        if (timeoutMs <= 0) return false;
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        try {
            for (ExecutorService pool : pools) {
                if (pool == null) continue;
                if (cancellation != null && cancellation.isCancelled()) pool.shutdownNow();
                else pool.shutdown();
                while (!pool.isTerminated()) {
                    if (cancellation != null && cancellation.isCancelled()) pool.shutdownNow();
                    long left = deadline - System.nanoTime();
                    if (left <= 0) return false;
                    pool.awaitTermination(Math.min(100L, Math.max(1L,
                            TimeUnit.NANOSECONDS.toMillis(left))), TimeUnit.MILLISECONDS);
                }
            }
            return true;
        } catch (InterruptedException error) {
            for (ExecutorService pool : pools) {
                if (pool != null) pool.shutdownNow();
            }
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
