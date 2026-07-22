FROM python:3.13-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./

RUN python -c 'import tomllib; from pathlib import Path; payload = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8")); print("\n".join(payload["project"]["dependencies"]))' \
    > /tmp/requirements.txt
RUN python -m pip install --upgrade pip "hatchling>=1.25" \
    && python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY cyberdeck ./cyberdeck
COPY cyberdeck_api ./cyberdeck_api
COPY integrations ./integrations
COPY config ./config
COPY scripts ./scripts

RUN python -m pip install --no-deps --no-build-isolation .
RUN mkdir -p /app/data /app/reports

EXPOSE 8000
CMD ["uvicorn", "cyberdeck_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
