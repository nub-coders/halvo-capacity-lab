# Docker baseline only. Never used to build or deploy Halvo applications.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-dev python3-venv python3-gdbm nginx ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --max-time 180 \
      https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz -o /tmp/node.tar.xz \
    && echo 'df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de  /tmp/node.tar.xz' | sha256sum -c - \
    && mkdir /opt/node && tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 \
    && rm /tmp/node.tar.xz
COPY benchmark.py probe.py guard.py /app/
RUN cd /app && python3 -c 'from pathlib import Path; import benchmark; benchmark.write_fixtures(Path("/app"))'
WORKDIR /app
USER 1000:1000
