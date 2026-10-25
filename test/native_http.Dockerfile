FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 util-linux \
    && rm -rf /var/lib/apt/lists
