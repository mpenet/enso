// ABOUTME: Caps open connections server-wide and per client address; checked by the acceptor
// ABOUTME: before a connection gets a thread, released when the connection closes.
package com.s_exp.enso.core;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

/**
 * Connection admission. {@link #tryAcquire} on accept, {@link #release}
 * exactly once per successful acquire when the connection closes. A limit
 * of 0 disables that check.
 *
 * <p>The global check is one atomic increment (and a decrement when over)
 * and allocates nothing. The per-address check costs a map update: counts
 * are boxed Integers (cached below 128, so no allocation for usual
 * counts), but an address's first open connection allocates a map node,
 * dropped again when its last one closes. Only enabled when
 * {@code :max-connections-per-ip} is set.
 */
public final class ConnectionLimiter {

    private static final BiFunction<InetAddress, Integer, Integer> INCREMENT =
        (address, count) -> count == null ? 1 : count + 1;
    private static final BiFunction<InetAddress, Integer, Integer> DECREMENT =
        (address, count) -> count == null || count <= 1 ? null : count - 1;

    private final int maxConnections;
    private final int maxPerAddress;
    private final AtomicInteger active = new AtomicInteger();
    private final ConcurrentHashMap<InetAddress, Integer> perAddress;

    public ConnectionLimiter(int maxConnections, int maxPerAddress) {
        this.maxConnections = maxConnections;
        this.maxPerAddress = maxPerAddress;
        this.perAddress = maxPerAddress > 0 ? new ConcurrentHashMap<>() : null;
    }

    /** Admits a connection from {@code address}, or returns false (close it). */
    public boolean tryAcquire(InetAddress address) {
        int total = active.incrementAndGet();
        if (maxConnections > 0 && total > maxConnections) {
            active.decrementAndGet();
            return false;
        }
        if (perAddress != null) {
            Integer count;
            try {
                count = perAddress.compute(address, INCREMENT);
            } catch (RuntimeException | Error e) {
                active.decrementAndGet();
                throw e;
            }
            if (count > maxPerAddress) {
                perAddress.compute(address, DECREMENT);
                active.decrementAndGet();
                return false;
            }
        }
        return true;
    }

    /** Releases a slot taken by a successful {@link #tryAcquire}. */
    public void release(InetAddress address) {
        if (perAddress != null) {
            perAddress.compute(address, DECREMENT);
        }
        active.decrementAndGet();
    }

    /** Connections currently admitted. */
    public int active() {
        return active.get();
    }
}
