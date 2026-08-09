# Interop-runner image for enso h3.
#
# Builds a self-contained Linux image with libquiche 0.29.3, JDK 25, the
# enso jar + JNI shim, and a run_endpoint.sh entry that speaks the
# quic-interop-runner contract (port 443 UDP, /certs/priv.key + cert.pem,
# /www files, TESTCASE env var).
#
# Build (from repo root):
#   docker buildx build --platform linux/amd64 \
#     -t enso-interop:latest \
#     -f bench/quic-interop-runner/Dockerfile .
#
# Test locally (single testcase):
#   docker run --rm -e TESTCASE=handshake -e SSLKEYLOGFILE=/logs/keys.log \
#     -v /tmp/certs:/certs -v /tmp/www:/www -v /tmp/logs:/logs \
#     enso-interop:latest

# ---- stage 1: build libquiche + our JNI shim + Java jar --------------------
FROM debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash build-essential ca-certificates cmake curl git \
    clang libclang-dev llvm-dev \
    libssl-dev libfontconfig1-dev pkg-config rlwrap \
    openjdk-25-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

# quiche 0.29.3 needs rustc >= 1.88; Debian trixie ships older. Use rustup
# to pin a recent stable toolchain.
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path

# Resolve JAVA_HOME per-arch (Debian's openjdk drops different arch dirs).
RUN if [ -d /usr/lib/jvm/java-25-openjdk-arm64 ]; then \
        ln -s /usr/lib/jvm/java-25-openjdk-arm64 /usr/lib/jvm/java-25-openjdk; \
    else \
        ln -s /usr/lib/jvm/java-25-openjdk-amd64 /usr/lib/jvm/java-25-openjdk; \
    fi
ENV JAVA_HOME=/usr/lib/jvm/java-25-openjdk

# Install Clojure CLI (canonical POSIX script — needs bash, not sh).
RUN curl -sSLO https://github.com/clojure/brew-install/releases/latest/download/posix-install.sh \
 && chmod +x posix-install.sh \
 && bash ./posix-install.sh \
 && rm posix-install.sh

# Build libquiche 0.29.3 with C FFI + BoringSSL vendor.
RUN git clone --depth 1 --branch 0.29.3 https://github.com/cloudflare/quiche.git /tmp/quiche \
 && cd /tmp/quiche \
 && cargo build --release --lib --features ffi,pkg-config-meta \
 && mkdir -p /opt/quiche/lib /opt/quiche/include \
 && cp target/release/libquiche.so /opt/quiche/lib/ \
 && cp quiche/include/quiche.h /opt/quiche/include/ \
 && rm -rf /tmp/quiche

# Copy enso sources.
WORKDIR /build
COPY deps.edn build.clj ./
COPY src ./src
COPY native ./native

# Build the JNI shim against the freshly compiled libquiche.
RUN JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac)))) \
    QUICHE_PREFIX=/opt/quiche \
    make -C native/enso_quiche

# Build the enso jar (includes shim under META-INF/native/linux-<arch>).
RUN clj -T:build jar

# ---- stage 2: runtime image ------------------------------------------------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl iproute2 rlwrap \
    openjdk-25-jre-headless \
 && rm -rf /var/lib/apt/lists/*

# Clojure CLI (runtime only). Pulls the Clojure jar into the local m2
# cache once the CLI is used; we prime it below so first request doesn't
# hit the network from inside the interop sandbox.
RUN curl -sSLO https://github.com/clojure/brew-install/releases/latest/download/posix-install.sh \
 && bash ./posix-install.sh \
 && rm posix-install.sh

# Prime the Clojure dep cache (Clojure jar + basis) so runtime doesn't
# need network — quic-interop-runner may sandbox the container.
RUN echo '{:paths ["."] :deps {org.clojure/clojure {:mvn/version "1.12.3"}}}' > /root/deps.edn \
 && cd /root && clj -Sdeps '{}' -M -e ':ok' >/dev/null 2>&1 || true \
 && rm /root/deps.edn

COPY --from=builder /opt/quiche/lib/libquiche.so /usr/lib/
COPY --from=builder /build/target/*.jar /opt/enso.jar
COPY --from=builder /build/target/native /opt/native
COPY bench/quic-interop-runner/deps.edn /opt/deps.edn
COPY bench/quic-interop-runner/run_endpoint.sh /run_endpoint.sh
COPY bench/quic-interop-runner/server.clj /opt/server.clj

RUN ldconfig && chmod +x /run_endpoint.sh

# quic-network-simulator waits on 4433 for readiness signal on stderr; we
# emit the standard "Listening" line from server.clj to unblock it.
ENV JAVA_TOOL_OPTIONS="--enable-native-access=ALL-UNNAMED -XX:+UseZGC"

EXPOSE 443/udp

ENTRYPOINT ["/run_endpoint.sh"]
