FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY src/ /app/src/

# Create directories
RUN mkdir -p /app/data /app/config

# Set Python to unbuffered mode
ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/src/main.py", "--config", "/app/config/config.yaml"]
