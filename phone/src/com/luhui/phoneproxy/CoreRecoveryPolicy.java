package com.luhui.phoneproxy;

/** Bounded exponential backoff for automatic recovery after core death. */
public final class CoreRecoveryPolicy {
    private static final int MAX_AUTOMATIC = 3;
    private int failures;
    private long nextAt;

    public synchronized boolean onPoll(boolean running, long now) {
        if (running) {
            failures = 0;
            nextAt = 0;
            return false;
        }
        if (failures >= MAX_AUTOMATIC || now < nextAt) return false;
        failures++;
        nextAt = now + Math.min(300000L, 5000L << Math.min(failures - 1, 6));
        return true;
    }

    public synchronized int failures() {
        return failures;
    }
}
