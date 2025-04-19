# Dockerfile

# 1) Builder stage: install deps
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install uv
COPY pyproject.toml uv.lock* ./
RUN uv pip install --system --no-cache .

# 2) Final stage: runtime
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages and uv executable
COPY --from=builder /usr/local/lib/python3.11/site-packages \
                   /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin                       /usr/local/bin

# Copy app code
COPY . .

# Tell Cloud Run (and you) the intended port
EXPOSE 8080

# Start Uvicorn on $PORT (default 8080), single process
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --log-level info"]
