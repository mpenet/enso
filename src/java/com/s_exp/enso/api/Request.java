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
import clojure.lang.ISeq;
import clojure.lang.Keyword;
import clojure.lang.MapEntry;
import clojure.lang.MapEquivalence;
import clojure.lang.Murmur3;
import clojure.lang.PersistentArrayMap;
import clojure.lang.RT;
import clojure.lang.Util;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

/**
 * Immutable per-request value carrier that also acts as the Ring request map.
 * Implements {@link IPersistentMap} directly so no Clojure wrapper is allocated
 * per request — handler code sees a fully-featured persistent map with
 * identity-checked keyword lookup and lazy caches for the derived Ring keys.
 * Equality, hashing, invocation as a function, metadata and reduce-kv follow
 * the persistent map contract, so a Request is interchangeable with the
 * equivalent literal map.
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
        K_SCHEME, K_REQUEST_METHOD, K_PROTOCOL, K_HEADERS, K_BODY
    };

    public final String method;
    public final String uri;
    public final String queryString;
    public final String protocol;
    public final IPersistentMap headers;
    public final InputStream body;
    public final int serverPort;
    /** Ring {@code :scheme} of the transport: {@link #K_HTTP} or {@link #K_HTTPS}. */
    public final Keyword scheme;

    private final InetAddress remoteAddress;
    private final IPersistentMap meta;
    private String remoteAddr;
    private Keyword methodKw;
    private String serverName;
    private Long serverPortValue;

    public Request(String method, String uri, String queryString, String protocol,
            IPersistentMap headers, InputStream body, InetAddress remoteAddress, int serverPort,
            Keyword scheme) {
        this.method = method;
        this.uri = uri;
        this.queryString = queryString;
        this.protocol = protocol;
        this.headers = headers;
        this.body = body;
        this.remoteAddress = remoteAddress;
        this.serverPort = serverPort;
        this.scheme = scheme;
        this.meta = null;
    }

    private Request(Request r, IPersistentMap meta) {
        this.method = r.method;
        this.uri = r.uri;
        this.queryString = r.queryString;
        this.protocol = r.protocol;
        this.headers = r.headers;
        this.body = r.body;
        this.remoteAddress = r.remoteAddress;
        this.serverPort = r.serverPort;
        this.scheme = r.scheme;
        this.meta = meta;
        this.remoteAddr = r.remoteAddr;
        this.methodKw = r.methodKw;
        this.serverName = r.serverName;
        this.serverPortValue = r.serverPortValue;
    }

    public String header(String name) {
        return (String) headers.valAt(name);
    }

    public String remoteAddr() {
        String v = remoteAddr;
        if (v == null) {
            v = remoteAddress.getHostAddress();
            remoteAddr = v;
        }
        return v;
    }

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
            v = extractServerName(host);
            serverName = v;
        }
        return v;
    }

    private static String extractServerName(String host) {
        if (host == null || host.isEmpty()) {
            return "localhost";
        }
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

    // ---- ILookup ----

    @Override
    public Object valAt(Object key) {
        return valAt(key, null);
    }

    @Override
    public Object valAt(Object key, Object notFound) {
        if (key == K_URI) return uri;
        if (key == K_REQUEST_METHOD) return methodKeyword();
        if (key == K_HEADERS) return headers;
        if (key == K_BODY) return body;
        if (key == K_QUERY_STRING) return queryString;
        if (key == K_SERVER_PORT) return serverPortValue();
        if (key == K_SERVER_NAME) return serverName();
        if (key == K_REMOTE_ADDR) return remoteAddr();
        if (key == K_SCHEME) return scheme;
        if (key == K_PROTOCOL) return protocol;
        return notFound;
    }

    // ---- IPersistentCollection ----

    @Override
    public int count() {
        return KEYS.length;
    }

    @Override
    public IPersistentCollection cons(Object o) {
        return materialize().cons(o);
    }

    @Override
    public IPersistentCollection empty() {
        return PersistentArrayMap.EMPTY.withMeta(meta);
    }

    @Override
    public boolean equiv(Object o) {
        if (o == this) return true;
        // Same contract as APersistentMap.equiv: maps compare by entries,
        // but a persistent map that isn't a MapEquivalence (e.g. a record)
        // never equals a plain map.
        if (!(o instanceof Map<?, ?> m)) return false;
        if (o instanceof IPersistentMap && !(o instanceof MapEquivalence)) return false;
        if (m.size() != KEYS.length) return false;
        for (Keyword k : KEYS) {
            if (!m.containsKey(k) || !Util.equiv(valAt(k), m.get(k))) return false;
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
        return meta;
    }

    @Override
    public Request withMeta(IPersistentMap meta) {
        if (meta == this.meta) return this;
        return new Request(this, meta);
    }

    // ---- IKVReduce ----

    @Override
    public Object kvreduce(IFn f, Object init) {
        for (Keyword k : KEYS) {
            init = f.invoke(init, k, valAt(k));
            if (RT.isReduced(init)) return ((IDeref) init).deref();
        }
        return init;
    }

    // ---- Associative ----

    @Override
    public boolean containsKey(Object key) {
        for (Keyword k : KEYS) {
            if (k == key) return true;
        }
        return false;
    }

    @Override
    public IMapEntry entryAt(Object key) {
        for (Keyword k : KEYS) {
            if (k == key) return MapEntry.create(k, valAt(k));
        }
        return null;
    }

    // ---- IPersistentMap ----

    @Override
    public IPersistentMap assoc(Object key, Object val) {
        return materialize().assoc(key, val);
    }

    @Override
    public IPersistentMap assocEx(Object key, Object val) {
        return materialize().assocEx(key, val);
    }

    @Override
    public IPersistentMap without(Object key) {
        return materialize().without(key);
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
            private int i = 0;

            @Override
            public boolean hasNext() {
                return i < KEYS.length;
            }

            @Override
            public IMapEntry next() {
                Keyword k = KEYS[i++];
                return MapEntry.create(k, valAt(k));
            }
        };
    }

    // ---- Map<Object, Object> ----

    @Override
    public int size() {
        return KEYS.length;
    }

    @Override
    public boolean isEmpty() {
        return false;
    }

    @Override
    public boolean containsValue(Object value) {
        return materializeMutable().containsValue(value);
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

    @Override
    public java.util.Set<Object> keySet() {
        return materializeMutable().keySet();
    }

    @Override
    public java.util.Collection<Object> values() {
        return materializeMutable().values();
    }

    @Override
    public java.util.Set<Map.Entry<Object, Object>> entrySet() {
        return materializeMutable().entrySet();
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
        Object[] arr = new Object[KEYS.length * 2];
        int i = 0;
        for (Keyword k : KEYS) {
            arr[i++] = k;
            arr[i++] = valAt(k);
        }
        return new PersistentArrayMap(meta, arr);
    }

    private Map<Object, Object> materializeMutable() {
        java.util.LinkedHashMap<Object, Object> m = new java.util.LinkedHashMap<>(KEYS.length * 2);
        for (Keyword k : KEYS) {
            m.put(k, valAt(k));
        }
        return m;
    }
}
