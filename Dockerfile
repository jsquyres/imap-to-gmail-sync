# Use Python 3.13 slim image as base
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install dependencies first (for better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY imap_sync_to_gmail.py .
COPY get_gmail_token.py .
COPY config.json.example .

# Create directory for user configuration and state files
RUN mkdir -p /data

# Set Python to run in unbuffered mode for better logging
ENV PYTHONUNBUFFERED=1

# Default command shows help
CMD ["python", "imap_sync_to_gmail.py", "--help"]
