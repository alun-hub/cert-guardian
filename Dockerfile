FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    pyyaml \
    requests

# Copy application files
COPY src/ /app/src/
COPY config/ /app/config/

# Create data directory
RUN mkdir -p /app/data

# Set Python to unbuffered mode for better logging
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "/app/src/main.py", "--config", "/app/config/config.yaml"]
