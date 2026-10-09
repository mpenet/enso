// ABOUTME: Minimum data rate for request bodies (:min-data-rate-bytes): how long a reader may still
// ABOUTME: wait for bytes before the body falls below the rate, from primitives the reader keeps.
package com.s_exp.enso.core;

/**
 * A read timeout restarts with every byte, so a client sending one byte
 * just inside {@code :read-timeout} holds its request (and the handler's
 * thread) forever. The minimum rate closes that: once a grace period is
 * spent waiting, the time a reader spends waiting for body bytes may not
 * exceed one second per {@code rate} bytes received (Kestrel's
 * MinRequestBodyDataRate). Only time spent waiting counts, so a handler
 * that reads slowly is never held against the client.
 *
 * <p>The reader keeps two primitives (bytes received, nanoseconds waited)
 * and bounds each wait by {@link #allowanceNanos}: no object, no timer,
 * one clock read on each side of a wait it would make anyway.
 */
public final class DataRate {

    private DataRate() {}

    /**
     * How long the next wait may last, in nanoseconds, before a body that
     * delivered {@code bytes} after {@code waitedNanos} of waiting falls
     * below {@code rate} bytes per second (with {@code graceNanos} of
     * waiting allowed on top). Zero or less: it already did. {@code rate}
     * 0 is off: {@link Long#MAX_VALUE}.
     */
    public static long allowanceNanos(long rate, long graceNanos, long bytes, long waitedNanos) {
        if (rate <= 0) return Long.MAX_VALUE;
        long earned = bytes / rate;
        if (earned >= Long.MAX_VALUE / 2_000_000_000L) return Long.MAX_VALUE;
        long nanos = earned * 1_000_000_000L + (bytes % rate) * 1_000_000_000L / rate;
        return graceNanos + nanos - waitedNanos;
    }
}
