package com.luhui.phoneproxy;

import java.util.concurrent.atomic.AtomicInteger;

/** Session generations make stale start/stop work unable to commit state. */
public final class LifecycleState {
    public static final class Session {
        public final int id;
        public final TaskControl control;
        Session(int id, TaskControl control) {
            this.id = id;
            this.control = control;
        }
    }

    private final AtomicInteger generation = new AtomicInteger();
    private volatile boolean stopped;
    private volatile TaskControl active;

    public synchronized Session begin() {
        if (active != null) active.cancel();
        stopped = false;
        TaskControl control = new TaskControl();
        active = control;
        return new Session(generation.incrementAndGet(), control);
    }

    /** Create a reload session only if no STOP/newer session won the race. */
    public synchronized Session begin(int expectedId) {
        if (stopped || generation.get() != expectedId) return null;
        return begin();
    }

    public synchronized int stop() {
        stopped = true;
        if (active != null) active.cancel();
        return generation.incrementAndGet();
    }

    public boolean isCurrent(Session session) {
        return session != null && !stopped && generation.get() == session.id
                && !session.control.isCancelled();
    }

    public TaskControl active() {
        return active;
    }

    public int currentId() {
        return generation.get();
    }
}
