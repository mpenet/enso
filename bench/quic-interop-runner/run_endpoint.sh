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

# Test cases enso supports as a server.
case "$TESTCASE" in
    handshake|transfer|retry|http3|multiconnect|longrtt|resumption|blackhole|amplificationlimit|handshakecorruption|handshakeloss|transfercorruption|transferloss|ipv6)
        ;;
    *)
        echo "TESTCASE=$TESTCASE unsupported" >&2
        exit 127
        ;;
esac

# The runner picks host 0.0.0.0:443; the framework NATs public IPs on top.
CERT=/certs/cert.pem
KEY=/certs/priv.key

# Emit the readiness marker the sim expects.
echo "server-side listening on 443/udp for testcase=$TESTCASE" >&2

export ENSO_QUICHE_SHIM=/opt/native/linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')/libenso_quiche.so

exec clj -Sdeps "$(cat /opt/deps.edn)" \
    -J-Denso.quiche.shim=$ENSO_QUICHE_SHIM \
    -M -i /opt/server.clj -e "(-main \"$TESTCASE\" \"$CERT\" \"$KEY\" \"/www\")"
