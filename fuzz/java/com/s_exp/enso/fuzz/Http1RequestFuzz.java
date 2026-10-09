// ABOUTME: Jazzer target for the HTTP/1.1 request parser and connection loop, run in-process over an
// ABOUTME: in-memory socket: arbitrary bytes must never escape as an exception or yield a 500 / bad output.
package com.s_exp.enso.fuzz;

import clojure.lang.Keyword;
import com.s_exp.enso.EnsoServer;
import com.s_exp.enso.api.Request;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.WebSocketListener;
import com.s_exp.enso.api.WebSocketSocket;
import com.s_exp.enso.http1.HttpConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The input is everything a client sends before half-closing: one or
 * more pipelined requests (bodies, chunked framing, trailers, a WebSocket
 * upgrade followed by frames...). The handler drains each request body
 * and answers 200 (or upgrades and echoes), so it never fails: a 500 in
 * the output is the server failing on its own. Checks: {@code run()}
 * returns without throwing, and the output is empty or starts with a
 * well-formed HTTP/1.1 status line.
 */
public final class Http1RequestFuzz {

    private static final Keyword BODY = Keyword.intern("body");
    private static final Map<String, String> HEADERS = Map.of("content-type", "text/plain");
    private static final byte[] INTERNAL_ERROR = "HTTP/1.1 500 ".getBytes(StandardCharsets.ISO_8859_1);

    private static final WebSocketListener ECHO = new WebSocketListener() {
        @Override
        public void onOpen(WebSocketSocket socket) {
        }

        @Override
        public void onMessage(WebSocketSocket socket, Object message) {
            try {
                if (message instanceof CharSequence s) {
                    socket.sendText(s);
                } else {
                    socket.sendBinary((ByteBuffer) message);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public void onClose(WebSocketSocket socket, int code, String reason) {
        }
    };

    private static final EnsoServer SERVER = FuzzServer.start(Http1RequestFuzz::handle);

    private Http1RequestFuzz() {}

    private static Response handle(Request request) {
        if ("websocket".equalsIgnoreCase(request.header("upgrade"))) {
            return new Response(101, Map.of(), null, ECHO, null);
        }
        Object body = request.valAt(BODY);
        if (body instanceof InputStream in) {
            try {
                in.transferTo(java.io.OutputStream.nullOutputStream());
            } catch (IOException e) {
                // A malformed or truncated body: the connection answers it.
            }
        }
        return new Response(200, HEADERS, "ok");
    }

    public static void fuzzerTestOneInput(byte[] data) {
        FakeSocket socket = new FakeSocket(data);
        new HttpConnection(socket, Http1RequestFuzz::handle, SERVER).run();
        byte[] out = socket.written();
        if (out.length == 0) return;
        if (!statusLine(out)) {
            throw new IllegalStateException("output does not start with an HTTP/1.1 status line: "
                + new String(out, 0, Math.min(out.length, 64), StandardCharsets.ISO_8859_1));
        }
        if (indexOf(out, INTERNAL_ERROR) >= 0) {
            throw new IllegalStateException("server answered 500 to client input:\n"
                + new String(out, StandardCharsets.ISO_8859_1));
        }
    }

    private static boolean statusLine(byte[] out) {
        if (out.length < 13) return false;
        if (!new String(out, 0, 9, StandardCharsets.ISO_8859_1).equals("HTTP/1.1 ")) return false;
        for (int i = 9; i < 12; i++) {
            if (out[i] < '0' || out[i] > '9') return false;
        }
        return out[9] >= '1' && out[9] <= '5' && out[12] == ' ';
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
