# GraalVM native image

enso links into a GraalVM native image. The HTTP/1.1, HTTP/2 and WebSocket
server needs no reflection or resource metadata. HTTP/3 does not go into the
image: it calls the quiche shim through JNI, so leave `:http3` off (the
default).

Two working examples: [examples/graalvm-clojure](../examples/graalvm-clojure)
uses the Clojure `run-server`, [examples/graalvm](../examples/graalvm) starts
the server from Java. Build and run either:

```
export GRAALVM_HOME=/path/to/graalvm   # or put native-image on PATH
examples/graalvm-clojure/build.sh
examples/graalvm-clojure/target/enso-native
```

```
curl http://127.0.0.1:8080/
```

## The Clojure example

`run-server` works unchanged. The entrypoint namespace is AOT-compiled with
`:gen-class`, which also compiles `s-exp.enso`.

```clojure
(ns example.server
  (:require [s-exp.enso :as enso])
  (:gen-class))

(defn -main [& _]
  (enso/run-server (fn [_] {:status 200 :body "hello\n"})
                   {:port 8080})
  @(promise))
```

## The Java example

Starting the server from Java keeps the image to the server and the handler
you write. The request map is still a Clojure data structure, so `clojure.lang`
is on the classpath either way.

```java
Config config = new Config.Builder().host("127.0.0.1").port(8080).build();
RingHandler handler = request ->
    new Response(200, Map.of("content-type", "text/plain"),
                 "hello\n".getBytes());
new EnsoServer(handler, config).start();
```

## The native-image flags

Clojure's classes initialise at build time through the
[graal-build-time](https://github.com/clj-easy/graal-build-time) feature. The
request map extends `clojure.lang.AFn`, so the Clojure runtime is part of the
image; the feature initialises it in the right order. Without it the build
fails in `clojure.lang.Compiler`.

```
--features=clj_easy.graal_build_time.InitClojureClasses
```

The Clojure example also initialises its own namespace and enso's Java packages
at build time. `s-exp.enso` builds a few Java objects as it loads (a rate
limiter, loggers); those objects can only live in the image when their classes
initialise at build time too.

```
--initialize-at-build-time=example.server,com.s_exp.enso
```

The classpath passed to `native-image` must list `target/classes` by an
absolute path, or be resolved from the repository root. `clojure -Spath`
prints it relative, so both `build.sh` scripts run `native-image` from the
repository root.

## TLS

The example serves TLS when `ENSO_TLS_CERT` and `ENSO_TLS_KEY` point at a PEM
certificate and key. The JVM's SSL engine works in the image with no extra
flags for RSA keys. An EC key also needs SunEC (`libsunec`, shipped with
GraalVM) reachable at run time.

```
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout key.pem -out cert.pem \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1

ENSO_TLS_CERT=cert.pem ENSO_TLS_KEY=key.pem examples/graalvm/target/enso-native
```

```
curl -k https://127.0.0.1:8443/
```
