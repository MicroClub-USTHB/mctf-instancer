FROM node:20-alpine AS frontend-builder

WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm ci --include=dev && npm install -D vite
COPY frontend/ ./
RUN npm run build


FROM python:3.11-slim

# Install Docker CLI and docker-compose plugin
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Overlay compiled SPA assets into FastAPI static directory
COPY --from=frontend-builder /build/app/static/index.html ./app/static/index.html
COPY --from=frontend-builder /build/app/static/admin.html ./app/static/admin.html
COPY --from=frontend-builder /build/app/static/assets ./app/static/assets

# Create challenges and data directories
RUN mkdir -p /challenges /app/data /app/logs

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
