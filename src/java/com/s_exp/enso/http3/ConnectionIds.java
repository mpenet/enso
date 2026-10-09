// ABOUTME: Server connection ids: generation with the owning event loop encoded in the first byte,
// ABOUTME: and an allocation-free open-addressing map from 16-byte ids to connections.
package com.s_exp.enso.http3;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

/**
 * Connection ids the server issues are {@link #LENGTH} bytes: the first
 * byte is the owning loop's index modulo the loop count (plus a random
 * multiple of it), the rest random. Datagrams are steered to their loop by
 * that byte alone (in the kernel on Linux, see
 * {@code UdpSocket#attachSteering}, else by the receiving loop).
 */
final class ConnectionIds {

    /** Length of every connection id the server issues. */
    static final int LENGTH = 16;

    private static final VarHandle LONGS =
        MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.nativeOrder());

    private ConnectionIds() {}

    /** A fresh id owned by loop {@code index} of {@code loops}. */
    static byte[] generate(SecureRandom rng, int index, int loops) {
        byte[] id = new byte[LENGTH];
        rng.nextBytes(id);
        int spread = 256 / loops;
        id[0] = (byte) (index + loops * ((id[0] & 0xFF) % spread));
        return id;
    }

    /** The loop owning an id whose first byte is {@code first}. */
    static int owner(int first, int loops) {
        return (first & 0xFF) % loops;
    }

    static long word(byte[] id, int i) {
        return (long) LONGS.get(id, i * 8);
    }

    /**
     * Open-addressing map from {@link #LENGTH}-byte ids to values. Lookups
     * read the id straight from a direct buffer and allocate nothing.
     * Linear probing with backward-shift deletion; the hash is keyed with a
     * per-map secret so peer-chosen ids can't be aimed at one probe chain.
     * One thread only.
     */
    static final class Map<V> {
        private static final long SEED_MIX = 0x9E3779B97F4A7C15L;

        private final long seed = new SecureRandom().nextLong() | 1L;
        private long[] k0;
        private long[] k1;
        private Object[] vals;
        private int mask;
        private int size;

        Map(int initialCapacity) {
            int cap = Integer.highestOneBit(Math.max(16, initialCapacity) - 1) << 1;
            k0 = new long[cap];
            k1 = new long[cap];
            vals = new Object[cap];
            mask = cap - 1;
        }

        int size() { return size; }

        @SuppressWarnings("unchecked")
        void forEach(java.util.function.Consumer<V> action) {
            Object[] vs = vals;
            for (Object v : vs) {
                if (v != null) action.accept((V) v);
            }
        }

        private int slot(long a, long b) {
            long h = (a ^ seed) * SEED_MIX;
            h ^= Long.rotateLeft(b ^ (seed >>> 7), 29) * 0xBF58476D1CE4E5B9L;
            h ^= h >>> 31;
            return (int) h & mask;
        }

        /** Value for the id in {@code buf[off, off + LENGTH)}, or null. */
        @SuppressWarnings("unchecked")
        V get(ByteBuffer buf, int off) {
            return find(buf.getLong(off), buf.getLong(off + 8));
        }

        @SuppressWarnings("unchecked")
        V get(byte[] id) {
            return find(word(id, 0), word(id, 1));
        }

        @SuppressWarnings("unchecked")
        private V find(long a, long b) {
            int i = slot(a, b);
            Object v;
            while ((v = vals[i]) != null) {
                if (k0[i] == a && k1[i] == b) return (V) v;
                i = (i + 1) & mask;
            }
            return null;
        }

        /** Maps {@code id} to {@code value} unless present; returns the existing value or null. */
        @SuppressWarnings("unchecked")
        V putIfAbsent(byte[] id, V value) {
            long a = word(id, 0), b = word(id, 1);
            int i = slot(a, b);
            Object v;
            while ((v = vals[i]) != null) {
                if (k0[i] == a && k1[i] == b) return (V) v;
                i = (i + 1) & mask;
            }
            k0[i] = a;
            k1[i] = b;
            vals[i] = value;
            if (++size * 2 > vals.length) grow();
            return null;
        }

        /** Removes {@code id} if it maps to {@code value}. */
        boolean remove(byte[] id, V value) {
            long a = word(id, 0), b = word(id, 1);
            int i = slot(a, b);
            Object v;
            while ((v = vals[i]) != null) {
                if (k0[i] == a && k1[i] == b) {
                    if (v != value) return false;
                    deleteAt(i);
                    return true;
                }
                i = (i + 1) & mask;
            }
            return false;
        }

        private void deleteAt(int hole) {
            vals[hole] = null;
            size--;
            int i = hole;
            while (true) {
                i = (i + 1) & mask;
                Object v = vals[i];
                if (v == null) return;
                int home = slot(k0[i], k1[i]);
                // Move i into the hole unless its home lies cyclically in (hole, i].
                boolean stays = hole <= i ? (hole < home && home <= i) : (hole < home || home <= i);
                if (!stays) {
                    k0[hole] = k0[i];
                    k1[hole] = k1[i];
                    vals[hole] = v;
                    vals[i] = null;
                    hole = i;
                }
            }
        }

        private void grow() {
            long[] o0 = k0, o1 = k1;
            Object[] ov = vals;
            int cap = ov.length * 2;
            k0 = new long[cap];
            k1 = new long[cap];
            vals = new Object[cap];
            mask = cap - 1;
            for (int j = 0; j < ov.length; j++) {
                if (ov[j] == null) continue;
                int i = slot(o0[j], o1[j]);
                while (vals[i] != null) i = (i + 1) & mask;
                k0[i] = o0[j];
                k1[i] = o1[j];
                vals[i] = ov[j];
            }
        }
    }
}
