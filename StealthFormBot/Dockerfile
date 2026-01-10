# Apify Python Actor Dockerfile
# Based on Apify's recommended Python base image
#
# This Dockerfile is designed for Apify deployment.
# The owl-browser SDK should be published to PyPI or bundled with the actor.

FROM apify/actor-python:3.12

# Install system dependencies for browser automation
RUN apt-get update && apt-get install -y \
    wget \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the owl-browser SDK (bundled with the actor)
# NOTE: For Apify deployment, copy the python-sdk folder into StealthFormBot/
# or publish owl-browser to PyPI and add it to requirements.txt
COPY owl_browser_sdk/ /app/owl_browser_sdk/
RUN pip install --no-cache-dir /app/owl_browser_sdk/ || echo "owl-browser SDK not bundled, assuming it's in requirements.txt"

# Copy actor source code
COPY . ./

# Set environment variables for Apify
ENV APIFY_LOCAL_STORAGE_DIR=/app/apify_storage
ENV APIFY_HEADLESS=1

# Create storage directories
RUN mkdir -p /app/apify_storage/datasets/default \
    /app/apify_storage/key_value_stores/default \
    /app/apify_storage/request_queues/default

# Run the actor
CMD ["python", "-m", "main"]
