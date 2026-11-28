package com.luhui.phoneproxy;

/** Cooperative cancellation token shared by network, testing and VPN lifecycle work. */
public interface Cancellation {
    boolean isCancelled();
}
