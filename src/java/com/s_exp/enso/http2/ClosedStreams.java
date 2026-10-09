// ABOUTME: Framer-confined memory of recently closed HTTP/2 streams and why they closed, with
// ABOUTME: constant-time lookup, so frames arriving on closed streams cost no scan of the history.
package com.s_exp.enso.http2;

/**
 * The last {@code capacity} streams to close, oldest forgotten first, each
 * with its closed reason ({@link Http2Stream#ENDED}, {@link Http2Stream#PEER_RESET},
 * {@link Http2Stream#WE_RESET}). A ring keeps the close order for
 * eviction; an open-addressing table (linear probing, backward-shift
 * deletion, at most half full) answers lookups. Client stream ids are
 * odd, so a table entry packs {@code id >>> 1} and the 2-bit reason into
 * one int, and 0 marks an empty slot. Both start small and grow with the
 * streams a connection actually closed, up to {@code capacity}.
 */
final class ClosedStreams {

    /** {@link #reasonOf}: an id at or below the highest the peer used that never opened. */
    static final int NEVER_OPENED = 0;
    /** {@link #reasonOf}: older than anything remembered. */
    static final int FORGOTTEN = -1;

    private static final int INITIAL = 8;

    private final int capacity;
    private int[] ring = new int[INITIAL];
    private int next;
    private boolean wrapped;
    // Highest id forgotten so far.
    private int floor;
    private int[] table = new int[INITIAL * 2];
    private int mask = INITIAL * 2 - 1;
    private int size;

    ClosedStreams(int capacity) {
        this.capacity = capacity;
    }

    /** Remembers that {@code id} closed for {@code reason} (1..3), forgetting the oldest when full. */
    void add(int id, int reason) {
        if (!wrapped && next == ring.length && ring.length < capacity) {
            // Not wrapped yet: the ring holds [0, next) in close order.
            ring = java.util.Arrays.copyOf(ring, Math.min(capacity, ring.length * 2));
        }
        int i = next;
        if (wrapped) {
            int old = ring[i];
            remove(old);
            if (old > floor) floor = old;
        }
        ring[i] = id;
        put(id, reason);
        int n = i + 1;
        if (n == ring.length && ring.length == capacity) {
            n = 0;
            wrapped = true;
        }
        next = n;
    }

    /** Why {@code id} closed, or {@link #NEVER_OPENED} / {@link #FORGOTTEN}. */
    int reasonOf(int id) {
        int key = id >>> 1;
        int i = slot(key);
        while (true) {
            int e = table[i];
            if (e == 0) break;
            if (e >>> 2 == key) return e & 3;
            i = (i + 1) & mask;
        }
        return id > floor ? NEVER_OPENED : FORGOTTEN;
    }

    private int slot(int key) {
        int h = key * 0x9E3779B9;
        return (h ^ (h >>> 16)) & mask;
    }

    private void put(int id, int reason) {
        if ((size + 1) * 2 > table.length) {
            int[] old = table;
            table = new int[old.length * 2];
            mask = table.length - 1;
            for (int e : old) {
                if (e != 0) insert(e);
            }
        }
        int key = id >>> 1;
        int i = slot(key);
        while (table[i] != 0) {
            if (table[i] >>> 2 == key) {
                table[i] = key << 2 | reason;
                return;
            }
            i = (i + 1) & mask;
        }
        table[i] = key << 2 | reason;
        size++;
    }

    private void insert(int entry) {
        int i = slot(entry >>> 2);
        while (table[i] != 0) {
            i = (i + 1) & mask;
        }
        table[i] = entry;
    }

    private void remove(int id) {
        int key = id >>> 1;
        int i = slot(key);
        while (true) {
            int e = table[i];
            if (e == 0) return;
            if (e >>> 2 == key) break;
            i = (i + 1) & mask;
        }
        size--;
        // Backward shift: pull later entries of the probe run into the gap.
        int gap = i;
        int j = i;
        while (true) {
            j = (j + 1) & mask;
            int e = table[j];
            if (e == 0) break;
            int home = slot(e >>> 2);
            if (((j - home) & mask) >= ((j - gap) & mask)) {
                table[gap] = e;
                gap = j;
            }
        }
        table[gap] = 0;
    }
}
