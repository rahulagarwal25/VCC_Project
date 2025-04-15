# Use Python base image
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (optional for Flask/Gunicorn)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Expose the service port
EXPOSE 5000

# Start using gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]