FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    nmap \
    sqlmap \
    dirb \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy VulnBuster source code
COPY . .

# Create necessary directories
RUN mkdir -p reports dynamic/logs kb audit

# Set environment variables
ENV PYTHONPATH=/app
ENV VULNBUSTER_HOME=/app

# Create non-root user
RUN useradd -m -u 1000 vulnbuster && chown -R vulnbuster:vulnbuster /app
USER vulnbuster

# Set entrypoint
ENTRYPOINT ["python", "main.py"]

# Default command
CMD ["--help"] 