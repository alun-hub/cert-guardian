FROM docker.io/python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY src/ /app/src/

# Create directories
RUN mkdir -p /app/data /app/config

# Set Python to unbuffered mode
ENV PYTHONUNBUFFERED=1
ENV TZ=Europe/Stockholm

CMD ["python", "/app/src/main.py", "--config", "/app/config/config.yaml"]
