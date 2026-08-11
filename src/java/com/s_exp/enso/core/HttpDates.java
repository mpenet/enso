package com.s_exp.enso.core;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Caches the IMF-fixdate representation of the current wall-clock second,
 * refreshed lazily. All three fields (second, string, byte-encoded header line)
 * are stored together behind one atomic reference so a reader can never see a
 * partial update — the previous complete snapshot is either replaced whole or
 * kept.
 */
public final class HttpDates {

    private static final DateTimeFormatter IMF_FIXDATE =
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)
            .withZone(ZoneOffset.UTC);

    private static final AtomicReference<Snapshot> CACHE =
        new AtomicReference<>(new Snapshot(-1, "", new byte[0]));

    private HttpDates() {
    }

    static String now() {
        return refresh().value;
    }

    /** Full "Date: ...\r\n" header line as ISO-8859-1 bytes. */
    public static byte[] dateLine() {
        return refresh().line;
    }

    private static Snapshot refresh() {
        long now = System.currentTimeMillis();
        long second = now / 1000;
        Snapshot cached = CACHE.get();
        if (second == cached.second) return cached;
        String value = IMF_FIXDATE.format(Instant.ofEpochMilli(now));
        byte[] line = ("Date: " + value + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        Snapshot fresh = new Snapshot(second, value, line);
        // CAS instead of blind set: under scheduler pauses a slow thread
        // computing second=N could overwrite a newer second=N+1 already
        // installed by a faster thread. CAS makes stale writes lose so
        // the cache always monotonically advances.
        while (!CACHE.compareAndSet(cached, fresh)) {
            cached = CACHE.get();
            if (cached.second >= second) return cached;
        }
        return fresh;
    }

    private static final class Snapshot {
        final long second;
        final String value;
        final byte[] line;

        Snapshot(long second, String value, byte[] line) {
            this.second = second;
            this.value = value;
            this.line = line;
        }
    }
}
