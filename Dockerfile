FROM python:3.11-slim

WORKDIR /app

# Install system deps for PyNaCl
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8000

# Bind to the platform-provided $PORT (falls back to 8000 locally).
CMD ["sh", "-c", "uvicorn auditskill.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
