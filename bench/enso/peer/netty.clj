;; ABOUTME: Netty 4.2 HTTP/3 target process for the cross-server comparison, answering every request
;; ABOUTME: with the hello response; a JDK HttpServer on the h1 port serves /__stats to the harness.
(ns enso.peer.netty
  "Run with `clojure -M:bench/netty h1 PORT h3 PORT`. Netty's HTTP/3 codec
  over its native quiche (BoringSSL) build, on one NIO event loop thread,
  which is what a single bound UDP channel uses. Flow-control limits and
  stream counts are set to enso's defaults, since Netty's are zero. The
  certificate is a self-signed RSA 2048 PEM pair, as for enso's HTTP/3
  listener."
  (:require [s-exp.enso-test-support :as support]
            [s-exp.perf-target :as target])
  (:import (com.sun.net.httpserver HttpExchange HttpHandler HttpServer)
           (io.netty.bootstrap Bootstrap)
           (io.netty.buffer Unpooled)
           (io.netty.channel Channel ChannelHandler ChannelHandlerContext ChannelInitializer EventLoopGroup
                             MultiThreadIoEventLoopGroup)
           (io.netty.channel.nio NioIoHandler)
           (io.netty.channel.socket.nio NioDatagramChannel)
           (io.netty.handler.codec.http3 DefaultHttp3DataFrame DefaultHttp3HeadersFrame Http3
                                         Http3RequestStreamInboundHandler Http3ServerConnectionHandler)
           (io.netty.handler.codec.quic InsecureQuicTokenHandler QuicServerCodecBuilder QuicSslContextBuilder QuicStreamChannel)
           (io.netty.util ReferenceCountUtil)
           (io.netty.util.concurrent GenericFutureListener)
           (java.io File)
           (java.net InetSocketAddress)
           (java.nio.charset StandardCharsets)
           (java.util.concurrent TimeUnit)))

(set! *warn-on-reflection* true)

(def ^:private body (.getBytes ^String target/hello-body StandardCharsets/US_ASCII))

(defn- request-handler
  "Answers a request stream once the client has finished sending it."
  ^ChannelHandler []
  (proxy [Http3RequestStreamInboundHandler] []
    (channelRead [_ frame]
      (ReferenceCountUtil/release frame))
    (channelInputClosed [^ChannelHandlerContext ctx]
      (let [headers (DefaultHttp3HeadersFrame.)]
        (doto (.headers headers)
          (.status "200")
          (.add "content-type" "text/plain")
          (.addInt "content-length" (alength ^bytes body)))
        (.write ctx headers)
        (-> (.writeAndFlush ctx (DefaultHttp3DataFrame. (Unpooled/wrappedBuffer ^bytes body)))
            (.addListener ^GenericFutureListener QuicStreamChannel/SHUTDOWN_OUTPUT))))))

(defn- start-h3
  "Binds the HTTP/3 server on UDP `port`; returns [group channel]."
  [port]
  (let [[cert key] (support/pem-cert-pair)
        group (MultiThreadIoEventLoopGroup. 1 (NioIoHandler/newFactory))
        ssl (-> (QuicSslContextBuilder/forServer (File. ^String key) nil (File. ^String cert))
                (.applicationProtocols (Http3/supportedApplicationProtocols))
                (.build))
        builder (doto ^QuicServerCodecBuilder (Http3/newQuicServerCodecBuilder)
                  (.sslContext ssl)
                  (.maxIdleTimeout 30000 TimeUnit/MILLISECONDS)
                  (.initialMaxData 524288)
                  (.initialMaxStreamDataBidirectionalLocal 262144)
                  (.initialMaxStreamDataBidirectionalRemote 262144)
                  (.initialMaxStreamDataUnidirectional 262144)
                  (.initialMaxStreamsBidirectional 100)
                  (.initialMaxStreamsUnidirectional 8)
                  (.tokenHandler InsecureQuicTokenHandler/INSTANCE)
                  (.handler (proxy [ChannelInitializer] []
                              (initChannel [^Channel ch]
                                (.addLast (.pipeline ch)
                                          (into-array ChannelHandler
                                                      [(Http3ServerConnectionHandler.
                                                        (proxy [ChannelInitializer] []
                                                          (initChannel [^Channel stream]
                                                            (.addLast (.pipeline stream)
                                                                      (into-array ChannelHandler [(request-handler)])))))]))))))
        codec (.build builder)
        channel (-> (Bootstrap.)
                    (.group group)
                    (.channel NioDatagramChannel)
                    (.handler codec)
                    (.bind (InetSocketAddress. "127.0.0.1" (int port)))
                    (.sync)
                    (.channel))]
    [group channel]))

(defn- start-stats
  "JDK HttpServer answering /__stats on TCP `port`."
  ^HttpServer [port]
  (doto (HttpServer/create (InetSocketAddress. "127.0.0.1" (int port)) 0)
    (.createContext "/__stats" (reify HttpHandler
                                 (handle [_ exchange]
                                   (let [^HttpExchange exchange exchange
                                         out (.getBytes (pr-str (target/stats)) StandardCharsets/UTF_8)]
                                     (.sendResponseHeaders exchange 200 (alength out))
                                     (with-open [os (.getResponseBody exchange)]
                                       (.write os out))))))
    (.start)))

(defn -main [& args]
  (let [{:keys [h1 h3] :as ports} (target/parse-args args)
        stats (start-stats h1)
        [^EventLoopGroup group ^Channel channel] (start-h3 h3)]
    (target/serve! ports (fn []
                           (.stop stats 0)
                           (.sync (.close channel))
                           (.sync (.shutdownGracefully group 0 500 TimeUnit/MILLISECONDS))))))
