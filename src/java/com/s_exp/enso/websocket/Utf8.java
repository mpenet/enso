// ABOUTME: Incremental UTF-8 validation (RFC 3629) over byte ranges, for WebSocket text messages
// ABOUTME: and CLOSE reasons: state carries across calls, ASCII runs are checked 8 bytes at a time.
package com.s_exp.enso.websocket;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * Validates UTF-8 as it arrives, so an invalid text message fails at the
 * frame holding the first invalid byte (RFC 6455 §8.1) rather than at the
 * message end, and is then decoded once by {@code new String(bytes, UTF_8)}.
 *
 * <p>The state is an int: {@link #ACCEPT} between characters,
 * {@link #REJECT} once invalid, otherwise the number of continuation bytes
 * still expected and the range the next one must fall in (RFC 3629 §4:
 * that range excludes overlong forms, surrogates and code points above
 * U+10FFFF, so they are rejected at the first byte that proves them).
 */
public final class Utf8 {

    public static final int ACCEPT = 0;
    public static final int REJECT = -1;

    private static final long HIGH_BITS = 0x8080808080808080L;
    private static final int ANY_CONTINUATION = 0x80BF;
    private static final VarHandle LONGS =
        MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

    private Utf8() {}

    /**
     * Validates {@code b[from..to)} continuing from {@code state} (the
     * result of the previous call, {@link #ACCEPT} for a new message).
     * Returns the state to continue from: {@link #ACCEPT} when the range
     * ends between characters, {@link #REJECT} once a byte can't be valid,
     * otherwise a character is incomplete.
     */
    public static int validate(byte[] b, int from, int to, int state) {
        int i = from;
        while (i < to) {
            if (state == ACCEPT) {
                while (i + 8 <= to && ((long) LONGS.get(b, i) & HIGH_BITS) == 0) {
                    i += 8;
                }
                if (i == to) {
                    break;
                }
                int c = b[i++] & 0xFF;
                if (c < 0x80) {
                    continue;
                }
                state = lead(c);
                if (state == REJECT) {
                    return REJECT;
                }
            } else {
                int c = b[i++] & 0xFF;
                if (c < ((state >>> 8) & 0xFF) || c > (state & 0xFF)) {
                    return REJECT;
                }
                int remaining = (state >>> 16) - 1;
                state = remaining == 0 ? ACCEPT : remaining << 16 | ANY_CONTINUATION;
            }
        }
        return state;
    }

    /** The state after lead byte {@code c} (0x80 and above). */
    private static int lead(int c) {
        if (c < 0xC2) {
            // A continuation byte, or C0 / C1 (overlong two-byte forms).
            return REJECT;
        }
        if (c < 0xE0) {
            return 1 << 16 | ANY_CONTINUATION;
        }
        if (c < 0xF0) {
            // E0: no overlong forms (A0..); ED: no surrogates (..9F).
            int lo = c == 0xE0 ? 0xA0 : 0x80;
            int hi = c == 0xED ? 0x9F : 0xBF;
            return 2 << 16 | lo << 8 | hi;
        }
        if (c < 0xF5) {
            // F0: no overlong forms (90..); F4: nothing past U+10FFFF (..8F).
            int lo = c == 0xF0 ? 0x90 : 0x80;
            int hi = c == 0xF4 ? 0x8F : 0xBF;
            return 3 << 16 | lo << 8 | hi;
        }
        return REJECT;
    }
}
