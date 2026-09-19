FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY sentinelmesh ./sentinelmesh

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .[intel,analytics,ssh]

EXPOSE 8000 8080 2121 2525 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"

CMD ["python", "-m", "sentinelmesh", "serve"]
