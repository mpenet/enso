// ABOUTME: A direct buffer whose native address is resolved once, so per-packet shim calls pass
// ABOUTME: (address, capacity) instead of making JNI look the buffer up on every call.
package com.s_exp.enso.quiche;

import java.nio.ByteBuffer;

/**
 * Direct memory shared with the shim: packets, socket address records,
 * per-datagram metadata. Only this package sees the address; the shim
 * checks every offset and length against {@link #capacity} before forming
 * a pointer, and this object keeps the memory reachable while it is used.
 * {@link #buffer} (native byte order) is the Java view.
 */
public final class NativeBuffer {

    /** Java view of the memory, in native byte order. */
    public final ByteBuffer buffer;
    final long address;
    public final int capacity;

    private NativeBuffer(ByteBuffer buffer) {
        this.buffer = buffer;
        this.capacity = buffer.capacity();
        long a = Quiche.bufferAddress(buffer);
        if (a == 0) throw new IllegalStateException("not a direct buffer");
        this.address = a;
    }

    public static NativeBuffer allocate(int capacity) {
        return new NativeBuffer(Records.allocate(capacity));
    }
}
