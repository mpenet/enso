# ABOUTME: quic-interop-runner endpoint image for enso as an HTTP/3 server: builds the static shim and
# ABOUTME: jar from the pinned native inputs, runs run_endpoint.sh on a JDK 25 runtime.
#
# Interop-runner image for enso h3.
#
# Builds a self-contained Linux image with JDK 25, the enso jar and the JNI
# shim statically linked against the pinned libquiche (as released: pins
# from native/enso_quiche/pins.env, built by build-libquiche.sh), and a
# run_endpoint.sh entry that speaks the quic-interop-runner contract (port
# 443 UDP, /certs/priv.key + cert.pem, /www files, TESTCASE env var).
# bench/quic-interop-runner/run.sh builds it and runs the runner.
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

# ---- stage 1: build static libquiche + our JNI shim + Java jar -------------
FROM debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash build-essential ca-certificates cmake curl git \
    clang libclang-dev llvm-dev \
    libssl-dev libfontconfig1-dev pkg-config rlwrap \
    openjdk-25-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

# The Rust toolchain pinned for release builds (Debian's is older than
# quiche needs).
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
COPY native/enso_quiche/pins.env /tmp/pins.env
RUN . /tmp/pins.env \
 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" --profile minimal --no-modify-path

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

# Copy enso sources.
WORKDIR /build
COPY deps.edn build.clj LICENSE NOTICE THIRD-PARTY-NOTICES ./
COPY src ./src
COPY native ./native

# Static libquiche (with BoringSSL) at the pinned commit and lockfile.
RUN native/enso_quiche/build-libquiche.sh /tmp/quiche

# Build the JNI shim against it.
RUN JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac)))) \
    make -C native/enso_quiche QUICHE_STATIC=1 \
      QUICHE_INCLUDE_DIR=/tmp/quiche/include QUICHE_LIB_DIR=/tmp/quiche/lib

# Build the enso jar (includes shim under META-INF/native/linux-<arch>).
# No git history in the build context: name the version explicitly.
RUN ENSO_VERSION=0.0.0-interop clj -T:build jar

# ---- stage 2: runtime image ------------------------------------------------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl ethtool iproute2 rlwrap \
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

COPY --from=builder /build/target/*.jar /opt/enso.jar
COPY --from=builder /build/target/native /opt/native
COPY bench/quic-interop-runner/deps.edn /opt/deps.edn
COPY bench/quic-interop-runner/run_endpoint.sh /run_endpoint.sh
COPY bench/quic-interop-runner/server.clj /opt/server.clj

RUN chmod +x /run_endpoint.sh

# quic-network-simulator waits on 4433 for readiness signal on stderr; we
# emit the standard "Listening" line from server.clj to unblock it.
ENV JAVA_TOOL_OPTIONS="--enable-native-access=ALL-UNNAMED -XX:+UseZGC"

EXPOSE 443/udp

ENTRYPOINT ["/run_endpoint.sh"]
