package com.luhui.phoneproxy;

/** Debounce network loss/capability churn before rebuilding the VPN core. */
public final class NetworkDebouncer {
    public static final String LOST = "__lost__";
    private static final long CHANGE_MS = 1500;
    private static final long LOSS_MS = 3000;
    private String applied;
    private String pending;
    private long dueAt;

    public synchronized String applied(String fingerprint, long now) {
        String previous = applied;
        applied = fingerprint;
        if (fingerprint != null && fingerprint.equals(pending)) {
            pending = null;
            dueAt = 0;
        }
        return previous == null ? fingerprint : previous;
    }

    public synchronized void onChange(String fingerprint, long now) {
        if (fingerprint == null) {
            pending = LOST;
            dueAt = now + LOSS_MS;
        } else if (LOST.equals(pending) || !fingerprint.equals(applied)) {
            pending = fingerprint;
            dueAt = now + CHANGE_MS;
        }
    }

    public synchronized String due(long now) {
        if (pending == null || now < dueAt) return null;
        String result = pending;
        pending = null;
        dueAt = 0;
        if (!LOST.equals(result)) applied = result;
        return result;
    }

    public synchronized void clear() {
        applied = null;
        pending = null;
        dueAt = 0;
    }
}
