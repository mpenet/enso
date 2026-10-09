// ABOUTME: Cursor over a fuzz input for the structured targets: reads bytes and big-endian integers,
// ABOUTME: yielding zeros once the input is exhausted, so every input decodes to some operation list.
package com.s_exp.enso.fuzz;

final class FuzzInput {

    private final byte[] data;
    private int pos;

    FuzzInput(byte[] data, int start) {
        this.data = data;
        this.pos = Math.min(start, data.length);
    }

    boolean hasMore() {
        return pos < data.length;
    }

    int u8() {
        return pos < data.length ? data[pos++] & 0xFF : 0;
    }

    int u16() {
        return (u8() << 8) | u8();
    }

    int u32() {
        return (u16() << 16) | u16();
    }

    /** The next {@code n} bytes, zero-filled past the end of the input. */
    byte[] bytes(int n) {
        byte[] b = new byte[n];
        int have = Math.max(0, Math.min(n, data.length - pos));
        System.arraycopy(data, pos, b, 0, have);
        pos += have;
        return b;
    }
}
