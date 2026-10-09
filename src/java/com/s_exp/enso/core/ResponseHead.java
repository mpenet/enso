// ABOUTME: Protocol-neutral, validated response head built from a handler's api.Response:
// ABOUTME: status, header fields, body kind and framing facts that every driver serialises from.
package com.s_exp.enso.core;

import clojure.lang.AFn;
import clojure.lang.IKVReduce;
import com.s_exp.enso.api.Response;
import com.s_exp.enso.api.StreamingBody;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.RandomAccess;
import java.util.function.BiConsumer;

/**
 * The response policy every protocol driver applies, computed once from
 * {@link Response} into reusable storage so a driver serialises straight
 * from it. One instance per connection (HTTP/1.1) or per writer; reused
 * across responses: {@link #prepare} then {@link #release}.
 *
 * <p>Rules ({@link #prepare} throws {@link IllegalArgumentException} for a
 * handler error; the driver answers 500 instead):
 * <ul>
 *   <li>Status: 200-599, or 101 when the response carries a WebSocket
 *       listener. Anything else (other 1xx included) is an error.
 *   <li>Field names are RFC 9110 tokens; values are RFC 9110 field values
 *       (no CTL but HTAB, nothing above U+00FF). Non-String values are
 *       snapshot once with {@code String.valueOf} and the snapshot is what
 *       is validated and sent; Long and Integer stay numbers. Nil values are
 *       skipped; a {@link List} value is one field per non-nil element.
 *   <li>Framing is the server's: Transfer-Encoding is always dropped; a
 *       handler Content-Length is dropped when the server knows the body
 *       length, kept (and parsed: 1*DIGIT) for stream bodies, HEAD and 304.
 *       1xx and 204 never carry one. Two Content-Length keys (differing
 *       in case) with different values are an error.
 *   <li>{@link #MULTIPLEXED} (HTTP/2, HTTP/3) drops connection-specific
 *       fields (Connection, Keep-Alive, Proxy-Connection, Upgrade) and
 *       lowercases names; {@link #HTTP1} keeps them as given and records a
 *       Connection: close in {@link #closeRequested}.
 *   <li>Date, Server and Alt-Svc are only noticed ({@link #hasDate} ...):
 *       drivers add theirs when absent, each in its cheapest encoding.
 * </ul>
 *
 * <p>Allocation: none for the common shapes (Clojure map headers with
 * String values, String/byte[]/nil bodies, ASCII text) once the field
 * arrays have grown to the response's size. Exceptions: lowercasing a
 * mixed-case name in multiplexed mode, String.valueOf of non-String,
 * non-integer values, a non-RandomAccess List value (iterator), encoding
 * non-ASCII text, and opening a File body.
 */
public final class ResponseHead {

    /** HTTP/1.1: names as given, connection-specific fields kept. */
    public static final int HTTP1 = 0;
    /** HTTP/2 and HTTP/3: lowercase names, connection-specific fields dropped. */
    public static final int MULTIPLEXED = 1;

    public static final int BODY_NONE = 0;
    public static final int BODY_BYTES = 1;
    /** A String whose chars are all ASCII in an ASCII-compatible charset: one byte per char. */
    public static final int BODY_ASCII = 2;
    public static final int BODY_FILE = 3;
    public static final int BODY_STREAM = 4;
    public static final int BODY_STREAMING = 5;

    private String[] names = new String[16];
    private Object[] values = new Object[16];
    private int fieldCount;

    private int status;
    private int mode;
    private boolean hasDate;
    private boolean hasServer;
    private boolean hasAltSvc;
    private boolean closeRequested;
    private boolean bodyAllowed;
    private long contentLength;
    private long declaredLength;
    private Object handlerContentLength;
    private Object contentType;

    private int bodyKind;
    private byte[] bytes;
    private String text;
    private File file;
    private FileChannel fileChannel;
    private InputStream stream;
    private StreamingBody streaming;

    private final Collector collector = new Collector();

    /**
     * Validates {@code response} and fills this head. {@code headRequest}:
     * the request was HEAD. A File body is opened here (so its length and
     * transfer agree) when its bytes will be sent. On failure the head is
     * left released and the response body is still the caller's to close.
     */
    public void prepare(Response response, boolean headRequest, int mode) {
        release();
        this.mode = mode;
        int s = response.status;
        if ((s < 200 || s > 599) && !(s == 101 && response.webSocketListener != null)) {
            throw new IllegalArgumentException("invalid response status " + s);
        }
        status = s;
        bodyAllowed = !headRequest && s >= 200 && s != 204 && s != 304;
        Map<?, ?> headers = response.headers;
        if (headers != null) {
            try {
                if (headers instanceof IKVReduce kv) {
                    kv.kvreduce(collector, null);
                } else {
                    headers.forEach(collector);
                }
            } catch (RuntimeException e) {
                release();
                throw e;
            }
        }
        try {
            classifyBody(response.body);
            frame();
        } catch (RuntimeException e) {
            // The body was not adopted (or was just closed): the caller
            // still owns response.body.
            closeFileChannel();
            clearRefs();
            throw e;
        }
    }

    /** Closes a body source that wasn't consumed and drops every reference. */
    public void release() {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ignored) {
            }
        }
        closeFileChannel();
        clearRefs();
    }

    /**
     * Hands the body source over to the caller (it now closes it). Call
     * before writing a stream body so {@link #release} leaves it alone.
     */
    public void disownBody() {
        stream = null;
        fileChannel = null;
    }

    private void closeFileChannel() {
        if (fileChannel != null) {
            try {
                fileChannel.close();
            } catch (IOException ignored) {
            }
        }
    }

    private void clearRefs() {
        for (int i = 0; i < fieldCount; i++) {
            names[i] = null;
            values[i] = null;
        }
        fieldCount = 0;
        hasDate = false;
        hasServer = false;
        hasAltSvc = false;
        closeRequested = false;
        handlerContentLength = null;
        contentType = null;
        contentLength = -1;
        declaredLength = -1;
        bodyKind = BODY_NONE;
        bytes = null;
        text = null;
        file = null;
        fileChannel = null;
        stream = null;
        streaming = null;
    }

    private void classifyBody(Object body) {
        if (body == null) {
            bodyKind = BODY_NONE;
        } else if (body instanceof String s) {
            Charset charset = charset();
            if (asciiCompatible(charset) && isAscii(s)) {
                bodyKind = BODY_ASCII;
                text = s;
            } else {
                bodyKind = BODY_BYTES;
                bytes = s.getBytes(charset);
            }
        } else if (body instanceof byte[] b) {
            bodyKind = BODY_BYTES;
            bytes = b;
        } else if (body instanceof File f) {
            bodyKind = BODY_FILE;
            file = f;
        } else if (body instanceof InputStream in) {
            bodyKind = BODY_STREAM;
            stream = in;
        } else if (body instanceof StreamingBody sb) {
            bodyKind = BODY_STREAMING;
            streaming = sb;
        } else {
            throw new IllegalArgumentException(
                "unsupported response body type: " + body.getClass().getName());
        }
    }

    /** Content-Length / declared length per the class rules. */
    private void frame() {
        contentLength = -1;
        declaredLength = -1;
        if (status < 200 || status == 204) {
            return;
        }
        long handlerLength = handlerContentLength == null ? -1 : parseLength(handlerContentLength);
        if (status == 304) {
            contentLength = handlerLength;
            return;
        }
        long known = knownLength();
        if (!bodyAllowed) {
            contentLength = handlerLength >= 0 ? handlerLength : known;
        } else if (known >= 0) {
            contentLength = known;
        } else if (handlerLength >= 0) {
            contentLength = handlerLength;
            declaredLength = handlerLength;
        }
    }

    private long knownLength() {
        switch (bodyKind) {
            case BODY_NONE:
                return 0;
            case BODY_BYTES:
                return bytes.length;
            case BODY_ASCII:
                return text.length();
            case BODY_FILE:
                if (!bodyAllowed) {
                    return file.length();
                }
                // One open + size() serves both Content-Length and the
                // transfer, so the two can't disagree.
                try {
                    fileChannel = FileChannel.open(file.toPath(), StandardOpenOption.READ);
                    return fileChannel.size();
                } catch (IOException e) {
                    throw new UncheckedIOException("unreadable response body file", e);
                }
            default:
                return -1;
        }
    }

    private Charset charset() {
        Object ct = contentType;
        return ct instanceof String s ? HttpFields.contentTypeCharset(s) : StandardCharsets.UTF_8;
    }

    private static boolean asciiCompatible(Charset c) {
        return c == StandardCharsets.UTF_8 || c == StandardCharsets.ISO_8859_1
            || c == StandardCharsets.US_ASCII || c.equals(StandardCharsets.UTF_8)
            || c.equals(StandardCharsets.ISO_8859_1) || c.equals(StandardCharsets.US_ASCII);
    }

    private static boolean isAscii(String s) {
        for (int i = 0, n = s.length(); i < n; i++) {
            if (s.charAt(i) > 127) return false;
        }
        return true;
    }

    /** 1*DIGIT (RFC 9110 §8.6), or a non-negative Long/Integer. */
    private static long parseLength(Object value) {
        long n;
        if (value instanceof Long || value instanceof Integer) {
            n = ((Number) value).longValue();
        } else {
            n = HttpFields.parseDigits(value instanceof String s ? s : String.valueOf(value));
        }
        if (n < 0) {
            throw new IllegalArgumentException("invalid Content-Length response header: " + value);
        }
        return n;
    }

    private void addField(String name, Object value) {
        if (fieldCount == names.length) {
            names = java.util.Arrays.copyOf(names, fieldCount * 2);
            values = java.util.Arrays.copyOf(values, fieldCount * 2);
        }
        names[fieldCount] = name;
        values[fieldCount] = value;
        fieldCount++;
    }

    /** Validates one handler field and records it. */
    private void onField(Object key, Object value) {
        if (value == null) return;
        String name = key instanceof String s ? s : String.valueOf(key);
        HttpFields.checkResponseName(name);
        // Dispatch on length first: most names match no special case.
        switch (name.length()) {
            case 4 -> {
                if (name.equalsIgnoreCase("date")) hasDate = true;
            }
            case 6 -> {
                if (name.equalsIgnoreCase("server")) hasServer = true;
            }
            case 7 -> {
                if (name.equalsIgnoreCase("alt-svc")) {
                    hasAltSvc = true;
                } else if (mode == MULTIPLEXED && name.equalsIgnoreCase("upgrade")) {
                    return;
                }
            }
            case 10 -> {
                if (name.equalsIgnoreCase("connection")) {
                    if (mode == MULTIPLEXED) return;
                    if (containsToken(value, "close")) closeRequested = true;
                } else if (mode == MULTIPLEXED && name.equalsIgnoreCase("keep-alive")) {
                    return;
                }
            }
            case 12 -> {
                if (name.equalsIgnoreCase("content-type")) contentType = value;
            }
            case 14 -> {
                if (name.equalsIgnoreCase("content-length")) {
                    // Keys differing only in case ("Content-Length" and
                    // "content-length") give two lengths: which one would
                    // frame the body is a guess, so disagreement is an error.
                    if (handlerContentLength != null && !handlerContentLength.equals(value)) {
                        throw new IllegalArgumentException("conflicting Content-Length response headers");
                    }
                    handlerContentLength = value;
                    return;
                }
            }
            case 16 -> {
                if (mode == MULTIPLEXED && name.equalsIgnoreCase("proxy-connection")) return;
            }
            case 17 -> {
                if (name.equalsIgnoreCase("transfer-encoding")) return;
            }
            default -> {
            }
        }
        if (mode == MULTIPLEXED) {
            name = HttpFields.toLowerAscii(name);
        }
        if (value instanceof List<?> list) {
            if (list instanceof RandomAccess) {
                for (int i = 0, n = list.size(); i < n; i++) {
                    addValue(name, list.get(i));
                }
            } else {
                for (Iterator<?> it = list.iterator(); it.hasNext(); ) {
                    addValue(name, it.next());
                }
            }
        } else {
            addValue(name, value);
        }
    }

    private void addValue(String name, Object value) {
        if (value == null) return;
        if (value instanceof Long || value instanceof Integer) {
            addField(name, value);
            return;
        }
        // Snapshot once: the exact String validated is the one sent.
        String v = value instanceof String s ? s : String.valueOf(value);
        HttpFields.checkResponseValue(v);
        addField(name, v);
    }

    private static boolean containsToken(Object value, String token) {
        if (value instanceof List<?> list) {
            for (Object v : list) {
                if (v != null && HttpFields.containsToken(String.valueOf(v), token)) return true;
            }
            return false;
        }
        return HttpFields.containsToken(String.valueOf(value), token);
    }

    /** Reused visitor over the handler's header map: IKVReduce for Clojure maps, forEach otherwise. */
    private final class Collector extends AFn implements BiConsumer<Object, Object> {
        @Override
        public Object invoke(Object acc, Object key, Object value) {
            onField(key, value);
            return acc;
        }

        @Override
        public void accept(Object key, Object value) {
            onField(key, value);
        }
    }

    // ---- Accessors ----------------------------------------------------------

    public int status() { return status; }

    public int fieldCount() { return fieldCount; }

    /** Fields the reusable storage holds without growing (a pool can drop heads that grew). */
    public int capacity() { return names.length; }

    /** Name of field {@code i}: as given (HTTP/1.1) or lowercase (multiplexed). */
    public String name(int i) { return names[i]; }

    /** Value of field {@code i}: a validated String, or a Long / Integer. */
    public Object value(int i) { return values[i]; }

    /** Value of field {@code i} as a String. */
    public String valueString(int i) {
        Object v = values[i];
        return v instanceof String s ? s : String.valueOf(v);
    }

    public boolean hasDate() { return hasDate; }

    public boolean hasServer() { return hasServer; }

    public boolean hasAltSvc() { return hasAltSvc; }

    /** HTTP/1.1 only: the handler sent Connection: close. */
    public boolean closeRequested() { return closeRequested; }

    /** False for HEAD requests and 1xx / 204 / 304: no body bytes are sent. */
    public boolean bodyAllowed() { return bodyAllowed; }

    /** Content-Length to send, or -1 for none. */
    public long contentLength() { return contentLength; }

    /**
     * The handler's Content-Length for a body whose length the server
     * doesn't know (stream, streaming), or -1. The driver must send exactly
     * this many bytes or abort the response.
     */
    public long declaredLength() { return declaredLength; }

    public int bodyKind() { return bodyKind; }

    public byte[] bytes() { return bytes; }

    /** {@link #BODY_ASCII} text, one byte per char. */
    public String text() { return text; }

    public File file() { return file; }

    /** Open channel of a {@link #BODY_FILE} body whose bytes will be sent, else null. */
    public FileChannel fileChannel() { return fileChannel; }

    public InputStream stream() { return stream; }

    public StreamingBody streaming() { return streaming; }
}
