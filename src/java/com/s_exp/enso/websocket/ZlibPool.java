// ABOUTME: Process-wide pool of the Deflaters permessage-deflate uses when nothing survives a
// ABOUTME: message (no server context takeover): borrowed per message, so idle sockets hold none.
package com.s_exp.enso.websocket;

import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.Deflater;

/**
 * Without the server's context takeover a connection's Deflater (about
 * 256 KiB of native memory) carries nothing from one message to the next,
 * so it is borrowed for the message and given back. The pool keeps at most
 * {@link #RETAINED} (enough for every core to compress at once, with room
 * for writers waiting on slow peers); beyond that, borrowing creates and
 * giving back frees.
 *
 * <p>A lock rather than a lock-free stack: a borrow or return is a few
 * field writes under an uncontended lock, and a ReentrantLock doesn't pin
 * a virtual thread's carrier.
 */
public final class ZlibPool {

    // Real-time messaging favours latency: level 1 compresses JSON-like
    // text to within ~10-15% of the default level at a fraction of the CPU.
    static final int LEVEL = Deflater.BEST_SPEED;

    static final int RETAINED = Math.max(8, 2 * Runtime.getRuntime().availableProcessors());

    private static final ReentrantLock LOCK = new ReentrantLock();
    private static final Deflater[] DEFLATERS = new Deflater[RETAINED];
    private static int deflaters;

    private ZlibPool() {}

    /** A raw (nowrap) Deflater at {@link #LEVEL}, reset. */
    public static Deflater deflater() {
        LOCK.lock();
        try {
            if (deflaters > 0) {
                Deflater d = DEFLATERS[--deflaters];
                DEFLATERS[deflaters] = null;
                return d;
            }
        } finally {
            LOCK.unlock();
        }
        return new Deflater(LEVEL, true);
    }

    /** Resets {@code d} and keeps it for the next borrower, or frees it. */
    public static void give(Deflater d) {
        d.reset();
        LOCK.lock();
        try {
            if (deflaters < RETAINED) {
                DEFLATERS[deflaters++] = d;
                return;
            }
        } finally {
            LOCK.unlock();
        }
        d.end();
    }
}
