FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /opt

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin spiderfoot

RUN git clone --depth 1 https://github.com/smicallef/spiderfoot.git /opt/spiderfoot

WORKDIR /opt/spiderfoot
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt \
    && python -m pip install fastapi==0.115.14 pydantic==2.11.7 "uvicorn[standard]==0.35.0" \
    && chown -R spiderfoot:spiderfoot /opt/spiderfoot /home/spiderfoot
RUN mkdir -p /home/spiderfoot/.spiderfoot/logs \
    && chown -R spiderfoot:spiderfoot /home/spiderfoot/.spiderfoot \
    && chmod 755 /home/spiderfoot

COPY app /opt/spiderfoot-sidecar/app
RUN chown -R spiderfoot:spiderfoot /opt/spiderfoot-sidecar

COPY spiderfoot-entrypoint.sh /usr/local/bin/spiderfoot-entrypoint.sh
RUN chmod +x /usr/local/bin/spiderfoot-entrypoint.sh

USER spiderfoot
EXPOSE 7020

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7020", "--app-dir", "/opt/spiderfoot-sidecar"]
