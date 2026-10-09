// ABOUTME: Small lock-free pool of ResponseHead instances: handler threads prepare a response into
// ABOUTME: one, the event loop encodes it and returns it, so steady-state responses allocate none.
package com.s_exp.enso.http3;

import com.s_exp.enso.core.ResponseHead;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * A bounded set of reusable {@link ResponseHead}s. {@link #acquire} from
 * any thread (a new head when the pool is empty), {@link #release} once
 * the head is released and no longer referenced; a head released into a
 * full pool is left to the GC.
 */
final class HeadPool {

    private final AtomicReferenceArray<ResponseHead> slots;
    private final int mask;

    HeadPool(int capacity) {
        int cap = Integer.highestOneBit(Math.max(2, capacity) - 1) << 1;
        slots = new AtomicReferenceArray<>(cap);
        mask = cap - 1;
    }

    private int start() {
        return (int) Thread.currentThread().threadId() & mask;
    }

    ResponseHead acquire() {
        int s = start();
        for (int i = 0; i <= mask; i++) {
            int j = (s + i) & mask;
            ResponseHead h = slots.getPlain(j);
            if (h != null && slots.compareAndSet(j, h, null)) return h;
        }
        return new ResponseHead();
    }

    void release(ResponseHead h) {
        int s = start();
        for (int i = 0; i <= mask; i++) {
            int j = (s + i) & mask;
            if (slots.getPlain(j) == null && slots.compareAndSet(j, null, h)) return;
        }
    }
}
