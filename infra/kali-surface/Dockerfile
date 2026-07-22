FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        amass \
        ca-certificates \
        curl \
        dnsrecon \
        dnsutils \
        httpx-toolkit \
        jq \
        nuclei \
        python3 \
        python3-venv \
        sslscan \
        subfinder \
        theharvester \
        tini \
        wafw00f \
        whatweb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir \
        fastapi==0.115.14 \
        pydantic==2.11.7 \
        uvicorn[standard]==0.35.0

RUN useradd --create-home --home-dir /home/surface --shell /usr/sbin/nologin surface \
    && mkdir -p /app /work \
    && chown -R surface:surface /app /work /home/surface

WORKDIR /app
COPY --chown=surface:surface app /app/app

USER surface
EXPOSE 7010

ENTRYPOINT ["tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7010"]
