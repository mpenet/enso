package com.s_exp.enso.util;

import java.util.function.LongFunction;

/**
 * Minimal primitive-{@code long}-keyed open-addressing hash map.
 * Non-thread-safe. Owner-thread only in h3 use-sites.
 *
 * <p>Motivation: {@code HashMap<Long, V>} autoboxes {@code long} keys on
 * every {@code put/get/remove}. Stream IDs grow past {@link Long}'s
 * value-cache (-128..127) very quickly under load, so each operation
 * allocates a fresh {@code Long}. Task #122 alloc profile showed this
 * as the top boxed primitive. This class stores keys in a
 * {@code long[]} and values in an {@code Object[]}, avoiding all
 * autoboxing on the hot path.
 *
 * <p>Uses linear probing + power-of-two capacity. Sentinel {@code 0} in
 * the key array marks empty slots; keys arriving with the actual value
 * {@code 0} are tracked in a dedicated {@link #zeroValue} slot. QUIC
 * stream ID {@code 0} is the first client-bidi stream, so this is
 * important.
 */
public final class Long2ObjectHashMap<V> {

    private static final int DEFAULT_INITIAL_CAPACITY = 16;
    private static final float LOAD_FACTOR = 0.6f;

    private long[] keys;
    private Object[] values;
    private int mask;
    private int size;
    private int resizeThreshold;

    private boolean hasZeroKey;
    private V zeroValue;

    public Long2ObjectHashMap() {
        this(DEFAULT_INITIAL_CAPACITY);
    }

    public Long2ObjectHashMap(int initialCapacity) {
        int cap = 1;
        while (cap < initialCapacity) cap <<= 1;
        this.keys = new long[cap];
        this.values = new Object[cap];
        this.mask = cap - 1;
        this.resizeThreshold = (int) (cap * LOAD_FACTOR);
    }

    public int size() { return size + (hasZeroKey ? 1 : 0); }

    public boolean isEmpty() { return size == 0 && !hasZeroKey; }

    @SuppressWarnings("unchecked")
    public V get(long key) {
        if (key == 0L) return hasZeroKey ? zeroValue : null;
        int i = index(key);
        while (true) {
            long k = keys[i];
            if (k == 0L) return null;
            if (k == key) return (V) values[i];
            i = (i + 1) & mask;
        }
    }

    /** @return previous value or null. */
    @SuppressWarnings("unchecked")
    public V put(long key, V value) {
        if (key == 0L) {
            V prev = zeroValue;
            zeroValue = value;
            hasZeroKey = true;
            return prev;
        }
        int i = index(key);
        while (true) {
            long k = keys[i];
            if (k == 0L) {
                keys[i] = key;
                values[i] = value;
                if (++size > resizeThreshold) resize();
                return null;
            }
            if (k == key) {
                V prev = (V) values[i];
                values[i] = value;
                return prev;
            }
            i = (i + 1) & mask;
        }
    }

    @SuppressWarnings("unchecked")
    public V remove(long key) {
        if (key == 0L) {
            if (!hasZeroKey) return null;
            V prev = zeroValue;
            zeroValue = null;
            hasZeroKey = false;
            return prev;
        }
        int i = index(key);
        while (true) {
            long k = keys[i];
            if (k == 0L) return null;
            if (k == key) {
                V prev = (V) values[i];
                // Standard open-addressing deletion: shift subsequent
                // entries in the run back so lookups don't stop at a
                // hole. See CLRS 11.4 / Knuth 6.4-D.
                keys[i] = 0L;
                values[i] = null;
                size--;
                int j = i;
                while (true) {
                    j = (j + 1) & mask;
                    long kj = keys[j];
                    if (kj == 0L) return prev;
                    int desired = index(kj);
                    if (leftDistance(desired, i) < leftDistance(j, i)) {
                        keys[i] = kj;
                        values[i] = values[j];
                        keys[j] = 0L;
                        values[j] = null;
                        i = j;
                    }
                }
            }
            i = (i + 1) & mask;
        }
    }

    /**
     * Get-or-compute idiom without boxing the key. If absent, invokes
     * {@code fn.apply(key)} and stores the returned value.
     */
    public V computeIfAbsent(long key, LongFunction<? extends V> fn) {
        V v = get(key);
        if (v != null) return v;
        v = fn.apply(key);
        if (v != null) put(key, v);
        return v;
    }

    public boolean containsKey(long key) {
        if (key == 0L) return hasZeroKey;
        int i = index(key);
        while (true) {
            long k = keys[i];
            if (k == 0L) return false;
            if (k == key) return true;
            i = (i + 1) & mask;
        }
    }

    public void clear() {
        java.util.Arrays.fill(keys, 0L);
        java.util.Arrays.fill(values, null);
        size = 0;
        hasZeroKey = false;
        zeroValue = null;
    }

    /**
     * Iterate all present entries. Callback receives (key, value); zero
     * key is included if present. Modification during iteration is not
     * supported.
     */
    public void forEach(EntryConsumer<V> action) {
        if (hasZeroKey) action.accept(0L, zeroValue);
        for (int i = 0; i < keys.length; i++) {
            long k = keys[i];
            if (k != 0L) {
                @SuppressWarnings("unchecked")
                V v = (V) values[i];
                action.accept(k, v);
            }
        }
    }

    @FunctionalInterface
    public interface EntryConsumer<V> {
        void accept(long key, V value);
    }

    // -----------------------------------------------------------------

    private int index(long key) {
        // Splittable64 mixer — cheap + good distribution.
        long h = key;
        h = (h ^ (h >>> 30)) * 0xbf58476d1ce4e5b7L;
        h = (h ^ (h >>> 27)) * 0x94d049bb133111ebL;
        h = h ^ (h >>> 31);
        return (int) h & mask;
    }

    private int leftDistance(int desired, int current) {
        return (current - desired) & mask;
    }

    private void resize() {
        long[] oldKeys = keys;
        Object[] oldValues = values;
        int newCap = keys.length * 2;
        keys = new long[newCap];
        values = new Object[newCap];
        mask = newCap - 1;
        resizeThreshold = (int) (newCap * LOAD_FACTOR);
        size = 0;
        for (int i = 0; i < oldKeys.length; i++) {
            long k = oldKeys[i];
            if (k != 0L) {
                @SuppressWarnings("unchecked")
                V v = (V) oldValues[i];
                put(k, v);
            }
        }
    }
}
