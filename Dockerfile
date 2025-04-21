# 1) Builder: install all Python deps into /install
FROM python:3.11-slim AS builder

# avoid .pyc files & buffered stdio
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy your manifest
COPY pyproject.toml uv.lock* ./

# Upgrade pip & install deps (including uvicorn!)
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir .

# Copy your app source (so any local packages get picked up too)
COPY . .



# 2) Runtime: only the installed site‑packages + your code
FROM python:3.11-slim

WORKDIR /app

# Copy the entire install tree
COPY --from=builder /install /usr/local
# Copy your application code
COPY . .

# Expose the port Cloud Run will send traffic to
EXPOSE 8080

# Use the exec form so signals are forwarded correctly
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]