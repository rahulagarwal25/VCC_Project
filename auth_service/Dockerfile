# Use an official Python runtime as a parent image
FROM python:3.10-slim

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=True
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8080  
ENV QR_KEY_MECHANISM=Dilithium3
ENV LOG_LEVEL=INFO
ENV JWT_SECRET="DEMO_JWT_SECRET_REPLACE_ME"
# Optionally set the blockchain node service URL here or override in K8s
# ENV BLOCKCHAIN_NODE_SVC_URL="http://blockchain-node-svc.qr-auth.svc.cluster.local:5000"

# Install system dependencies required for oqs-python and cryptographic libs
# Install system dependencies and build liboqs from source
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev git python3-dev \
    && git clone --branch main https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs && mkdir build && cd build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_BUILD_SHARED_LIBS=ON .. \
    && ninja && ninja install \
    && cd /app && rm -rf /liboqs \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port the app runs on
EXPOSE 8080

# Run the application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
