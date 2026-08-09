#!/usr/bin/env bash
# quic-interop-runner endpoint entry.
#
# Contract (see repo/quic.md):
#   TESTCASE      selects behaviour; unsupported → exit 127
#   /certs/       priv.key + cert.pem
#   /www/         files to serve (server mode)
#   /downloads/   destination (client mode; unused here — server only)
#   REQUESTS      space-separated URLs (client mode; ignored server-side)
#   SSLKEYLOGFILE NSS key-log path
#   QLOGDIR       qlog output dir (ignored — libquiche 0.29.3 supports but
#                 we don't wire it up yet)

set -euo pipefail

TESTCASE="${TESTCASE:-handshake}"

# Test cases enso supports as a server. The interop-runner defaults most
# transport tests to ALPN "hq-interop" (HTTP/0.9-over-QUIC) — we only
# implement HTTP/3, so we opt out of those and only claim tests that
# negotiate ALPN "h3". The "http3" testcase covers the transport +
# handshake + tiny transfer over real HTTP/3.
case "$TESTCASE" in
    http3)
        ;;
    *)
        echo "TESTCASE=$TESTCASE unsupported" >&2
        exit 127
        ;;
esac

# The runner picks host 0.0.0.0:443; the framework NATs public IPs on top.
CERT=/certs/cert.pem
KEY=/certs/priv.key

# Route client subnets via the sim on rightnet. Without this, response
# packets to 193.167.0.0/24 go to Docker's default gateway and never
# reach the client. Standard quic-interop endpoint images do this via
# their base setup.sh; we roll our own since we don't derive from that
# base.
ip route add 193.167.0.0/24 via 193.167.100.2 || true
ip -6 route add fd00:cafe:cafe:0::/64 via fd00:cafe:cafe:100::2 || true

# Emit the readiness marker the sim expects.
echo "server-side listening on 443/udp for testcase=$TESTCASE" >&2

export ENSO_QUICHE_SHIM=/opt/native/linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')/libenso_quiche.so

exec clojure -Sdeps "$(cat /opt/deps.edn)" \
    -J-Denso.quiche.shim=$ENSO_QUICHE_SHIM \
    -M -i /opt/server.clj -e "(-main \"$TESTCASE\" \"$CERT\" \"$KEY\" \"/www\")"
