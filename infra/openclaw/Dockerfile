FROM ghcr.io/openclaw/openclaw:2026.6.6

USER root
COPY --chown=node:node openclaw.json /opt/cyberdecision/openclaw.json
COPY entrypoint.sh /usr/local/bin/cde-openclaw-entrypoint
RUN chmod 755 /usr/local/bin/cde-openclaw-entrypoint
USER node

ENTRYPOINT ["/usr/local/bin/cde-openclaw-entrypoint"]
