# Use an official Python runtime as a parent image
FROM python:3.11-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install uv (faster package installer)
RUN pip install uv

# Copy dependency definition files
COPY pyproject.toml uv.lock* ./

# Install dependencies using uv into the system Python environment
# Using --system avoids creating a virtualenv inside the container
# Using --no-cache reduces layer size
RUN uv pip install --system --no-cache .

# --- Final Stage ---
FROM python:3.11-slim

WORKDIR /app

# Copy installed dependencies from the builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run the application using Uvicorn
# Uvicorn will automatically use the $PORT environment variable if set (by Cloud Run),
# otherwise it defaults to 8000 (useful for local testing without PORT set).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0"] 