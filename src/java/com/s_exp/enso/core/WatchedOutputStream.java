// ABOUTME: OutputStream that brackets every write to the wrapped transport with a WriteWatchdog,
// ABOUTME: in bounded slices, and counts bytes written for request accounting.
package com.s_exp.enso.core;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Sits directly on a transport stream (socket or TLS). Writes are cut into
 * slices of at most {@link #SLICE_BYTES} so a single large write still
 * reports progress per slice: write-timeout then means "no slice of 256
 * KiB completed for that long", i.e. the peer drains slower than 256 KiB
 * per timeout. One instance per connection; not thread-safe beyond the
 * transport's own one-writer-at-a-time rule.
 */
public final class WatchedOutputStream extends OutputStream {

    /** Largest write handed to the transport at once. */
    public static final int SLICE_BYTES = 256 * 1024;

    private final OutputStream out;
    private final WriteWatchdog watchdog;
    private long bytesWritten;

    public WatchedOutputStream(OutputStream out, WriteWatchdog watchdog) {
        this.out = out;
        this.watchdog = watchdog;
    }

    /** Total bytes handed to the transport so far. */
    public long bytesWritten() {
        return bytesWritten;
    }

    @Override
    public void write(int b) throws IOException {
        watchdog.enter();
        try {
            out.write(b);
        } finally {
            watchdog.exit();
        }
        bytesWritten++;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = Math.min(len, SLICE_BYTES);
            watchdog.enter();
            try {
                out.write(b, off, n);
            } finally {
                watchdog.exit();
            }
            bytesWritten += n;
            off += n;
            len -= n;
        }
    }

    @Override
    public void flush() throws IOException {
        watchdog.enter();
        try {
            out.flush();
        } finally {
            watchdog.exit();
        }
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}
