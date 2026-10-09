# ABOUTME: Linux host image for running bench/quic-interop-runner/run.sh where the runner can't run natively
# ABOUTME: (macOS): tshark >= 4.5, Docker CLI + Compose talking to the host daemon, Python 3.12.
#
# The runner creates its per-test directories under /tmp and bind-mounts
# them into the simulator containers, so its /tmp must be the Docker
# daemon's /tmp (Docker Desktop: the VM's), and the repository must be
# mounted at the same path as on the host. See doc/testing.md.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends software-properties-common gpg-agent ca-certificates \
      curl git openssl python3 python3-venv \
 && add-apt-repository -y ppa:wireshark-dev/stable \
 && apt-get update \
 && apt-get install -y --no-install-recommends tshark \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*
