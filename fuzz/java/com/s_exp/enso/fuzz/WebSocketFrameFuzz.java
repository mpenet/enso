// ABOUTME: Jazzer target for the WebSocket frame parser and connection loop, run in-process over an
// ABOUTME: in-memory socket: the read loop must end, call onClose exactly once and emit only valid frames.
package com.s_exp.enso.fuzz;

import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.WebSocketListener;
import com.s_exp.enso.api.WebSocketSocket;
import com.s_exp.enso.websocket.PerMessageDeflate;
import com.s_exp.enso.websocket.WebSocketConnection;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;

/**
 * Input layout: byte 0 bit 0 selects a permessage-deflate connection,
 * the rest is the client's frame stream (then EOF). The listener echoes
 * every message. Checks: {@code run()} returns without throwing,
 * {@code onClose} ran exactly once, and the server's output parses as a
 * sequence of unmasked frames with known opcodes, RSV1 only on the first
 * frame of a compressed data message, control frames unfragmented and at
 * most 125 bytes, and a close payload of 0 or at least 2 bytes.
 */
public final class WebSocketFrameFuzz {

    private static final EnsoServer SERVER = FuzzServer.start(request -> null);

    private WebSocketFrameFuzz() {}

    public static void fuzzerTestOneInput(byte[] data) {
        if (data.length == 0) return;
        boolean compressed = (data[0] & 1) != 0;
        PerMessageDeflate deflate = compressed ? PerMessageDeflate.negotiate("permessage-deflate") : null;
        FakeSocket socket = new FakeSocket(java.util.Arrays.copyOfRange(data, 1, data.length));
        int[] closes = new int[1];
        WebSocketListener listener = new WebSocketListener() {
            @Override
            public void onOpen(WebSocketSocket s) {
            }

            @Override
            public void onMessage(WebSocketSocket s, Object message) {
                try {
                    if (message instanceof CharSequence text) {
                        s.sendText(text);
                    } else {
                        s.sendBinary((ByteBuffer) message);
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }

            @Override
            public void onClose(WebSocketSocket s, int code, String reason) {
                closes[0]++;
            }
        };
        new WebSocketConnection(socket, socket.getInputStream(), socket.getOutputStream(), listener,
            SERVER.config(), deflate, SERVER.timer(), SERVER.service().budget).run();
        if (closes[0] != 1) {
            throw new IllegalStateException("onClose ran " + closes[0] + " times");
        }
        if (!socket.isClosed()) {
            throw new IllegalStateException("run() returned with the socket open");
        }
        checkFrames(socket.written(), compressed);
    }

    private static void checkFrames(byte[] out, boolean compressed) {
        int p = 0;
        boolean inMessage = false;
        while (p < out.length) {
            if (out.length - p < 2) throw new IllegalStateException("truncated frame header at " + p);
            int b0 = out[p] & 0xFF;
            int b1 = out[p + 1] & 0xFF;
            boolean fin = (b0 & 0x80) != 0;
            boolean rsv1 = (b0 & 0x40) != 0;
            int opcode = b0 & 0x0F;
            if ((b0 & 0x30) != 0) throw new IllegalStateException("RSV2/RSV3 set at " + p);
            if ((b1 & 0x80) != 0) throw new IllegalStateException("server frame masked at " + p);
            long len = b1 & 0x7F;
            int h = 2;
            if (len == 126) {
                if (out.length - p < 4) throw new IllegalStateException("truncated length at " + p);
                len = ((out[p + 2] & 0xFF) << 8) | (out[p + 3] & 0xFF);
                h = 4;
            } else if (len == 127) {
                if (out.length - p < 10) throw new IllegalStateException("truncated length at " + p);
                len = 0;
                for (int i = 2; i < 10; i++) len = (len << 8) | (out[p + i] & 0xFF);
                h = 10;
            }
            if (len < 0 || len > out.length - p - h) throw new IllegalStateException("frame overruns output at " + p);
            boolean control = opcode >= 8;
            if (control) {
                if (opcode > 10) throw new IllegalStateException("unknown control opcode " + opcode);
                if (!fin || len > 125 || rsv1) throw new IllegalStateException("invalid control frame at " + p);
                if (opcode == 8 && len == 1) throw new IllegalStateException("1-byte close payload at " + p);
            } else {
                if (opcode > 2) throw new IllegalStateException("unknown data opcode " + opcode);
                if (opcode == 0 && !inMessage) throw new IllegalStateException("continuation outside a message at " + p);
                if (opcode != 0 && inMessage) throw new IllegalStateException("new message inside a message at " + p);
                if (rsv1 && (!compressed || opcode == 0)) throw new IllegalStateException("unexpected RSV1 at " + p);
                inMessage = !fin;
            }
            p += h + (int) len;
        }
    }
}
