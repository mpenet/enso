// ABOUTME: Framer-confined map from stream id to stream: open addressing on int keys, so the
// ABOUTME: lookup on every DATA / HEADERS / WINDOW_UPDATE frame neither boxes ids nor locks.
package com.s_exp.enso.http2;

/**
 * Linear probing with backward-shift deletion (no tombstones), load
 * factor at most one half. Only the framer thread touches it; other
 * threads hand closed streams back through the connection's retired
 * stack and the framer removes them.
 */
final class Http2StreamTable {

    private int[] keys;
    private Http2Stream[] values;
    private int mask;
    private int size;

    Http2StreamTable() {
        keys = new int[16];
        values = new Http2Stream[16];
        mask = 15;
    }

    private static int hash(int id) {
        int h = id * 0x9E3779B9;
        return h ^ (h >>> 16);
    }

    Http2Stream get(int id) {
        int i = hash(id) & mask;
        while (true) {
            int k = keys[i];
            if (k == id) return values[i];
            if (k == 0) return null;
            i = (i + 1) & mask;
        }
    }

    void put(int id, Http2Stream s) {
        if ((size + 1) * 2 > keys.length) {
            resize(keys.length * 2);
        }
        int i = hash(id) & mask;
        while (keys[i] != 0 && keys[i] != id) {
            i = (i + 1) & mask;
        }
        if (keys[i] == 0) size++;
        keys[i] = id;
        values[i] = s;
    }

    void remove(int id) {
        int i = hash(id) & mask;
        while (keys[i] != id) {
            if (keys[i] == 0) return;
            i = (i + 1) & mask;
        }
        size--;
        // Backward shift: pull later entries of the probe run into the gap.
        int gap = i;
        int j = i;
        while (true) {
            j = (j + 1) & mask;
            int k = keys[j];
            if (k == 0) break;
            int home = hash(k) & mask;
            // Move k into the gap unless its home lies cyclically in (gap, j].
            if (((j - home) & mask) >= ((j - gap) & mask)) {
                keys[gap] = k;
                values[gap] = values[j];
                gap = j;
            }
        }
        keys[gap] = 0;
        values[gap] = null;
        // Shrink back after a burst of streams, keeping idle connections small.
        if (keys.length > 64 && size * 8 < keys.length) {
            resize(keys.length / 2);
        }
    }

    /** Slots for iteration: {@link #slot} of 0 until capacity, null where empty. */
    int capacity() {
        return keys.length;
    }

    Http2Stream slot(int i) {
        return values[i];
    }

    void clear() {
        java.util.Arrays.fill(keys, 0);
        java.util.Arrays.fill(values, null);
        size = 0;
    }

    private void resize(int capacity) {
        int[] oldKeys = keys;
        Http2Stream[] oldValues = values;
        keys = new int[capacity];
        values = new Http2Stream[capacity];
        mask = capacity - 1;
        size = 0;
        for (int i = 0; i < oldKeys.length; i++) {
            if (oldKeys[i] != 0) {
                put(oldKeys[i], oldValues[i]);
            }
        }
    }
}
