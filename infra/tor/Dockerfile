FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl netcat-openbsd tini tor \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc

RUN chmod 0644 /etc/tor/torrc

EXPOSE 9050

USER debian-tor
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["tor", "-f", "/etc/tor/torrc"]
