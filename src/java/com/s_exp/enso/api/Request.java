// ABOUTME: The Ring request map: an IPersistentMap over the parsed request with lazily computed
// ABOUTME: Ring keys; assoc / dissoc keep it lazy by layering changes over the base fields.
package com.s_exp.enso.api;

import clojure.lang.AFn;
import clojure.lang.APersistentMap;
import clojure.lang.IDeref;
import clojure.lang.IFn;
import clojure.lang.IHashEq;
import clojure.lang.IKVReduce;
import clojure.lang.IMapEntry;
import clojure.lang.IObj;
import clojure.lang.IPersistentCollection;
import clojure.lang.IPersistentMap;
import clojure.lang.IPersistentVector;
import clojure.lang.ISeq;
import clojure.lang.Keyword;
import clojure.lang.MapEntry;
import clojure.lang.MapEquivalence;
import clojure.lang.Murmur3;
import clojure.lang.PersistentArrayMap;
import clojure.lang.PersistentHashMap;
import clojure.lang.RT;
import clojure.lang.Util;
import com.s_exp.enso.core.TlsSocket;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * Immutable per-request value carrier that also acts as the Ring request map.
 * Implements {@link IPersistentMap} directly so no Clojure wrapper is allocated
 * per request — handler code sees a fully-featured persistent map with
 * identity-checked keyword lookup and lazy caches for the derived Ring keys.
 * Equality, hashing, invocation as a function, metadata and reduce-kv follow
 * the persistent map contract, so a Request is interchangeable with the
 * equivalent literal map.
 *
 * <p>{@code assoc} and {@code dissoc} return a Request too: added keys and
 * replaced base keys live in a small persistent map layered over the base
 * fields, and a bit per base key records that it was replaced or removed.
 * Middleware adding keys therefore never forces the lazy keys
 * ({@code :remote-addr}, {@code :server-name}, ...) to be computed.
 *
 * <p>{@code :ssl-client-cert} is always present: the peer's
 * {@link X509Certificate} on a TLS connection that verified one, nil
 * otherwise. {@code :body} is nil when the request has no body.
 */
public final class Request extends AFn
        implements IPersistentMap, Map<Object, Object>, MapEquivalence, IHashEq, IObj, IKVReduce {

    static final Keyword K_SERVER_PORT = Keyword.intern("server-port");
    static final Keyword K_SERVER_NAME = Keyword.intern("server-name");
    static final Keyword K_REMOTE_ADDR = Keyword.intern("remote-addr");
    static final Keyword K_URI = Keyword.intern("uri");
    static final Keyword K_QUERY_STRING = Keyword.intern("query-string");
    static final Keyword K_SCHEME = Keyword.intern("scheme");
    static final Keyword K_REQUEST_METHOD = Keyword.intern("request-method");
    static final Keyword K_PROTOCOL = Keyword.intern("protocol");
    static final Keyword K_HEADERS = Keyword.intern("headers");
    static final Keyword K_BODY = Keyword.intern("body");
    static final Keyword K_SSL_CLIENT_CERT = Keyword.intern("ssl-client-cert");
    public static final Keyword K_HTTP = Keyword.intern("http");
    public static final Keyword K_HTTPS = Keyword.intern("https");

    private static final Keyword M_GET = Keyword.intern("get");
    private static final Keyword M_POST = Keyword.intern("post");
    private static final Keyword M_PUT = Keyword.intern("put");
    private static final Keyword M_DELETE = Keyword.intern("delete");
    private static final Keyword M_HEAD = Keyword.intern("head");
    private static final Keyword M_OPTIONS = Keyword.intern("options");
    private static final Keyword M_PATCH = Keyword.intern("patch");
    private static final Keyword M_TRACE = Keyword.intern("trace");
    private static final Keyword M_CONNECT = Keyword.intern("connect");

    private static final Keyword[] KEYS = {
        K_SERVER_PORT, K_SERVER_NAME, K_REMOTE_ADDR, K_URI, K_QUERY_STRING,
        K_SCHEME, K_REQUEST_METHOD, K_PROTOCOL, K_HEADERS, K_BODY, K_SSL_CLIENT_CERT
    };
    private static final int ALL_KEYS = (1 << KEYS.length) - 1;

    // Lookup sentinel: "not a base key".
    private static final Object NONE = new Object();

    public final String method;
    public final String uri;
    public final String queryString;
    public final String protocol;
    public final IPersistentMap headers;
    public final InputStream body;
    public final int serverPort;
    /** Ring {@code :scheme} of the transport: {@link #K_HTTP} or {@link #K_HTTPS}. */
    public final Keyword scheme;

    // The connection's socket (remote and local address, TLS session), or
    // the remote InetAddress when there is no socket (HTTP/3).
    private final Object peer;
    // Metadata and assoc / dissoc changes; null for a request as parsed,
    // so the common lookup is one null check.
    private final Overlay overlay;
    private String remoteAddr;
    private Keyword methodKw;
    private String serverName;
    private Long serverPortValue;
    // NO_CERT once looked up and absent.
    private Object sslClientCert;

    private static final Object NO_CERT = new Object();

    /**
     * What withMeta, assoc and dissoc layered over the base fields.
     * {@code ext} holds added keys and replaced base keys; bit i of
     * {@code hidden} marks KEYS[i] replaced or removed (its value, if any,
     * is in ext).
     */
    private static final class Overlay {
        final IPersistentMap meta;
        final IPersistentMap ext;
        final int hidden;

        Overlay(IPersistentMap meta, IPersistentMap ext, int hidden) {
            this.meta = meta;
            this.ext = ext;
            this.hidden = hidden;
        }
    }

    public Request(String method, String uri, String queryString, String protocol,
            IPersistentMap headers, InputStream body, InetAddress remoteAddress, int serverPort,
            Keyword scheme) {
        this(method, uri, queryString, protocol, headers, body, remoteAddress, serverPort, scheme, null);
    }

    /**
     * {@code connection} is the request's socket (a TLS adapter socket on
     * TLS), read only when a handler asks for {@code :ssl-client-cert} or
     * for {@code :server-name} of a request without a Host.
     */
    public Request(String method, String uri, String queryString, String protocol,
            IPersistentMap headers, InputStream body, InetAddress remoteAddress, int serverPort,
            Keyword scheme, Socket connection) {
        this.method = method;
        this.uri = uri;
        this.queryString = queryString;
        this.protocol = protocol;
        this.headers = headers;
        this.body = body;
        this.serverPort = serverPort;
        this.scheme = scheme;
        this.peer = connection != null ? connection : remoteAddress;
        this.overlay = null;
    }

    /**
     * As above, for the request after {@code previous} on the same
     * connection (null for the first): what {@code previous} derived from
     * the connection is reused rather than derived again (one String or
     * Long per request each): {@code :remote-addr}, {@code :server-port},
     * {@code :ssl-client-cert}, and {@code :server-name} when the Host
     * value is the same String (a driver reusing repeated header values
     * hands back the same one).
     */
    public Request(String method, String uri, String queryString, String protocol,
            IPersistentMap headers, InputStream body, InetAddress remoteAddress, int serverPort,
            Keyword scheme, Socket connection, Request previous) {
        this(method, uri, queryString, protocol, headers, body, remoteAddress, serverPort, scheme, connection);
        if (previous != null && previous.peer == peer) {
            // previous may be read on another thread, filling these racily:
            // each holds one immutable value derived from the connection.
            remoteAddr = previous.remoteAddr;
            sslClientCert = previous.sslClientCert;
            if (previous.serverPort == serverPort) {
                serverPortValue = previous.serverPortValue;
            }
            String name = previous.serverName;
            if (name != null && previous.headers.valAt("host") == headers.valAt("host")) {
                serverName = name;
            }
        }
    }

    private Request(Request r, IPersistentMap meta, IPersistentMap ext, int hidden) {
        this.method = r.method;
        this.uri = r.uri;
        this.queryString = r.queryString;
        this.protocol = r.protocol;
        this.headers = r.headers;
        this.body = r.body;
        this.serverPort = r.serverPort;
        this.scheme = r.scheme;
        this.peer = r.peer;
        this.overlay = meta == null && ext == null && hidden == 0 ? null : new Overlay(meta, ext, hidden);
        this.remoteAddr = r.remoteAddr;
        this.methodKw = r.methodKw;
        this.serverName = r.serverName;
        this.serverPortValue = r.serverPortValue;
        this.sslClientCert = r.sslClientCert;
    }

    private IPersistentMap ext() {
        Overlay o = overlay;
        return o == null ? null : o.ext;
    }

    private int hidden() {
        Overlay o = overlay;
        return o == null ? 0 : o.hidden;
    }

    public String header(String name) {
        return (String) headers.valAt(name);
    }

    public String remoteAddr() {
        String v = remoteAddr;
        if (v == null) {
            v = formatAddress(peer instanceof Socket s ? s.getInetAddress() : (InetAddress) peer);
            remoteAddr = v;
        }
        return v;
    }

    /**
     * An address as text, as {@code :remote-addr} has it: dotted IPv4, or
     * IPv6 in the RFC 5952 canonical form (lowercase, the longest run of two
     * or more zero groups as "::", the leftmost on a tie), without a zone
     * index. For {@link ServerEvents} listeners, so their addresses match
     * the request's.
     */
    public static String formatAddress(InetAddress address) {
        if (!(address instanceof Inet6Address)) {
            return address.getHostAddress();
        }
        byte[] b = address.getAddress();
        int bestStart = -1;
        int bestLen = 1;
        for (int i = 0; i < 8; ) {
            if (group(b, i) != 0) {
                i++;
                continue;
            }
            int j = i;
            while (j < 8 && group(b, j) == 0) {
                j++;
            }
            if (j - i > bestLen) {
                bestStart = i;
                bestLen = j - i;
            }
            i = j;
        }
        StringBuilder sb = new StringBuilder(39);
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen - 1;
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
                sb.append(':');
            }
            sb.append(Integer.toHexString(group(b, i)));
        }
        return sb.toString();
    }

    private static int group(byte[] b, int i) {
        return ((b[2 * i] & 0xFF) << 8) | (b[2 * i + 1] & 0xFF);
    }

    // Methods are tokens bounded by the head size limit. Keywords are
    // interned, in a table of weak references, so an extension method's
    // keyword lives only as long as requests using it.
    private Keyword methodKeyword() {
        Keyword k = methodKw;
        if (k == null) {
            k = switch (method) {
                case "GET" -> M_GET;
                case "POST" -> M_POST;
                case "PUT" -> M_PUT;
                case "DELETE" -> M_DELETE;
                case "HEAD" -> M_HEAD;
                case "OPTIONS" -> M_OPTIONS;
                case "PATCH" -> M_PATCH;
                case "TRACE" -> M_TRACE;
                case "CONNECT" -> M_CONNECT;
                default -> Keyword.intern(method.toLowerCase(Locale.ROOT));
            };
            methodKw = k;
        }
        return k;
    }

    // Boxed once, as a Long like any Clojure integer literal, so the
    // request equals the equivalent map under Object.equals too.
    private Long serverPortValue() {
        Long v = serverPortValue;
        if (v == null) {
            v = (long) serverPort;
            serverPortValue = v;
        }
        return v;
    }

    private String serverName() {
        String v = serverName;
        if (v == null) {
            String host = (String) headers.valAt("host");
            v = host == null || host.isEmpty() ? localAddress() : extractServerName(host);
            serverName = v;
        }
        return v;
    }

    /**
     * The address the request came in on, IPv6 bracketed as in a Host
     * header; "localhost" when there is no socket to ask.
     */
    private String localAddress() {
        if (peer instanceof Socket connection) {
            SocketAddress local = connection.getLocalSocketAddress();
            if (local instanceof InetSocketAddress isa && isa.getAddress() != null) {
                InetAddress a = isa.getAddress();
                String s = formatAddress(a);
                return a instanceof Inet6Address ? "[" + s + "]" : s;
            }
        }
        return "localhost";
    }

    private static String extractServerName(String host) {
        // IPv6 hosts use the bracketed form `[::1]:8080`.
        if (host.charAt(0) == '[') {
            int close = host.indexOf(']');
            if (close < 0) {
                return host;
            }
            return host.substring(0, close + 1);
        }
        int colon = host.lastIndexOf(':');
        return colon < 0 ? host : host.substring(0, colon);
    }

    private X509Certificate sslClientCert() {
        Object c = sslClientCert;
        if (c == null) {
            X509Certificate cert = peerCertificate(peer);
            c = cert == null ? NO_CERT : cert;
            sslClientCert = c;
        }
        return c == NO_CERT ? null : (X509Certificate) c;
    }

    private static X509Certificate peerCertificate(Object peer) {
        if (!(peer instanceof TlsSocket.AdapterSocket tls)) {
            return null;
        }
        try {
            Certificate[] chain = tls.tls().session().getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate x ? x : null;
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    /** The value of base key {@code KEYS[i]}. */
    private Object baseValue(int i) {
        return switch (i) {
            case 0 -> serverPortValue();
            case 1 -> serverName();
            case 2 -> remoteAddr();
            case 3 -> uri;
            case 4 -> queryString;
            case 5 -> scheme;
            case 6 -> methodKeyword();
            case 7 -> protocol;
            case 8 -> headers;
            case 9 -> body;
            default -> sslClientCert();
        };
    }

    /** Index of {@code key} in KEYS, or -1. */
    private static int indexOf(Object key) {
        if (key == K_URI) return 3;
        if (key == K_REQUEST_METHOD) return 6;
        if (key == K_HEADERS) return 8;
        if (key == K_BODY) return 9;
        if (key == K_QUERY_STRING) return 4;
        if (key == K_SERVER_PORT) return 0;
        if (key == K_SERVER_NAME) return 1;
        if (key == K_REMOTE_ADDR) return 2;
        if (key == K_SCHEME) return 5;
        if (key == K_PROTOCOL) return 7;
        if (key == K_SSL_CLIENT_CERT) return 10;
        return -1;
    }

    private boolean visible(int i) {
        return (hidden() & (1 << i)) == 0;
    }

    // ---- ILookup ----

    @Override
    public Object valAt(Object key) {
        return valAt(key, null);
    }

    @Override
    public Object valAt(Object key, Object notFound) {
        int i = indexOf(key);
        Overlay o = overlay;
        if (o == null) {
            return i >= 0 ? baseValue(i) : notFound;
        }
        if (i >= 0 && (o.hidden & (1 << i)) == 0) {
            return baseValue(i);
        }
        return o.ext == null ? notFound : o.ext.valAt(key, notFound);
    }

    // ---- IPersistentCollection ----

    @Override
    public int count() {
        IPersistentMap ext = ext();
        return Integer.bitCount(~hidden() & ALL_KEYS) + (ext == null ? 0 : ext.count());
    }

    @Override
    public IPersistentCollection cons(Object o) {
        // As APersistentMap.cons: a map entry, a [k v] pair, or a map.
        if (o instanceof Map.Entry<?, ?> e) {
            return assoc(e.getKey(), e.getValue());
        }
        if (o instanceof IPersistentVector v) {
            if (v.count() != 2) {
                throw new IllegalArgumentException("Vector arg to map conj must be a pair");
            }
            return assoc(v.nth(0), v.nth(1));
        }
        IPersistentMap ret = this;
        for (ISeq es = RT.seq(o); es != null; es = es.next()) {
            Map.Entry<?, ?> e = (Map.Entry<?, ?>) es.first();
            ret = ret.assoc(e.getKey(), e.getValue());
        }
        return ret;
    }

    @Override
    public IPersistentCollection empty() {
        return PersistentArrayMap.EMPTY.withMeta(meta());
    }

    @Override
    public boolean equiv(Object o) {
        if (o == this) return true;
        // Same contract as APersistentMap.equiv: maps compare by entries,
        // but a persistent map that isn't a MapEquivalence (e.g. a record)
        // never equals a plain map.
        if (!(o instanceof Map<?, ?> m)) return false;
        if (o instanceof IPersistentMap && !(o instanceof MapEquivalence)) return false;
        if (m.size() != count()) return false;
        for (Iterator<IMapEntry> it = iterator(); it.hasNext(); ) {
            IMapEntry e = it.next();
            Object k = e.key();
            if (!m.containsKey(k) || !Util.equiv(e.val(), m.get(k))) return false;
        }
        return true;
    }

    // ---- IHashEq ----

    @Override
    public int hasheq() {
        return Murmur3.hashUnordered(this);
    }

    // ---- IFn ----

    @Override
    public Object invoke(Object key) {
        return valAt(key);
    }

    @Override
    public Object invoke(Object key, Object notFound) {
        return valAt(key, notFound);
    }

    // ---- IObj ----

    @Override
    public IPersistentMap meta() {
        Overlay o = overlay;
        return o == null ? null : o.meta;
    }

    @Override
    public Request withMeta(IPersistentMap meta) {
        if (meta == meta()) return this;
        return new Request(this, meta, ext(), hidden());
    }

    // ---- IKVReduce ----

    @Override
    public Object kvreduce(IFn f, Object init) {
        for (int i = 0; i < KEYS.length; i++) {
            if (visible(i)) {
                init = f.invoke(init, KEYS[i], baseValue(i));
                if (RT.isReduced(init)) return ((IDeref) init).deref();
            }
        }
        IPersistentMap ext = ext();
        if (ext != null) {
            for (Object o : ext) {
                IMapEntry e = (IMapEntry) o;
                init = f.invoke(init, e.key(), e.val());
                if (RT.isReduced(init)) return ((IDeref) init).deref();
            }
        }
        return init;
    }

    // ---- Associative ----

    @Override
    public boolean containsKey(Object key) {
        int i = indexOf(key);
        if (i >= 0 && visible(i)) return true;
        IPersistentMap ext = ext();
        return ext != null && ext.containsKey(key);
    }

    @Override
    public IMapEntry entryAt(Object key) {
        int i = indexOf(key);
        if (i >= 0 && visible(i)) return MapEntry.create(KEYS[i], baseValue(i));
        IPersistentMap ext = ext();
        return ext == null ? null : ext.entryAt(key);
    }

    // ---- IPersistentMap ----

    @Override
    public IPersistentMap assoc(Object key, Object val) {
        IPersistentMap ext = ext();
        IPersistentMap e = (ext == null ? PersistentArrayMap.EMPTY : ext).assoc(key, val);
        int i = indexOf(key);
        int hidden = hidden();
        return new Request(this, meta(), e, i < 0 ? hidden : hidden | (1 << i));
    }

    @Override
    public IPersistentMap assocEx(Object key, Object val) {
        if (containsKey(key)) {
            throw Util.runtimeException("Key already present");
        }
        return assoc(key, val);
    }

    @Override
    public IPersistentMap without(Object key) {
        int i = indexOf(key);
        IPersistentMap ext = ext();
        int hidden = hidden();
        boolean inExt = ext != null && ext.containsKey(key);
        boolean inBase = i >= 0 && visible(i);
        if (!inExt && !inBase) {
            return this;
        }
        IPersistentMap e = ext;
        if (inExt) {
            e = ext.without(key);
            if (e.count() == 0) {
                e = null;
            }
        }
        return new Request(this, meta(), e, i < 0 ? hidden : hidden | (1 << i));
    }

    // ---- Seqable ----

    @Override
    public ISeq seq() {
        return materialize().seq();
    }

    // ---- Iterable<IMapEntry> (from IPersistentMap) ----

    @Override
    public Iterator<IMapEntry> iterator() {
        return new Iterator<>() {
            private int i = nextVisible(0);
            private final Iterator<?> rest = ext() == null ? null : ext().iterator();

            private int nextVisible(int from) {
                while (from < KEYS.length && !visible(from)) {
                    from++;
                }
                return from;
            }

            @Override
            public boolean hasNext() {
                return i < KEYS.length || (rest != null && rest.hasNext());
            }

            @Override
            public IMapEntry next() {
                if (i < KEYS.length) {
                    IMapEntry e = MapEntry.create(KEYS[i], baseValue(i));
                    i = nextVisible(i + 1);
                    return e;
                }
                if (rest == null) {
                    throw new NoSuchElementException();
                }
                return (IMapEntry) rest.next();
            }
        };
    }

    // ---- Map<Object, Object> ----

    @Override
    public int size() {
        return count();
    }

    @Override
    public boolean isEmpty() {
        return count() == 0;
    }

    @Override
    public boolean containsValue(Object value) {
        for (Iterator<IMapEntry> it = iterator(); it.hasNext(); ) {
            if (Util.equiv(it.next().val(), value)) return true;
        }
        return false;
    }

    @Override
    public Object get(Object key) {
        return valAt(key);
    }

    @Override
    public Object put(Object key, Object value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object remove(Object key) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void putAll(Map<?, ?> m) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException();
    }

    // Read-only views, as on any persistent map.

    @Override
    @SuppressWarnings("unchecked")
    public java.util.Set<Object> keySet() {
        return ((Map<Object, Object>) materialize()).keySet();
    }

    @Override
    @SuppressWarnings("unchecked")
    public java.util.Collection<Object> values() {
        return ((Map<Object, Object>) materialize()).values();
    }

    @Override
    @SuppressWarnings("unchecked")
    public java.util.Set<Map.Entry<Object, Object>> entrySet() {
        return ((Map<Object, Object>) materialize()).entrySet();
    }

    // ---- equals / hashCode ----

    @Override
    public boolean equals(Object o) {
        return APersistentMap.mapEquals(this, o);
    }

    @Override
    public int hashCode() {
        return APersistentMap.mapHash(this);
    }

    // ---- helpers ----

    private IPersistentMap materialize() {
        Object[] arr = new Object[count() * 2];
        int n = 0;
        for (Iterator<IMapEntry> it = iterator(); it.hasNext(); ) {
            IMapEntry e = it.next();
            arr[n++] = e.key();
            arr[n++] = e.val();
        }
        // Clojure keeps array maps to 8 entries; beyond, a hash map.
        IPersistentMap meta = meta();
        return arr.length <= 16 ? new PersistentArrayMap(meta, arr) : PersistentHashMap.create(meta, arr);
    }
}
