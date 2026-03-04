FROM nvidia/cuda:12.1.1-cudnn8-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11=3.11.* \
    python3.11-dev=3.11.* \
    python3-pip=23.* \
    git=1:2.* \
    patch=2.* \
    curl=7.* \
    wget=1.* \
    docker.io=24.* \
    ca-certificates=20* \
    && rm -rf /var/lib/apt/lists/*

# Install Grype for CVE scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy for Dockerfile config scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.0

# Python setup
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade "pip==24.*" && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Verify Grype and Trivy are available
RUN grype version && trivy --version

# Default: run the patch agent API server
EXPOSE 8080
CMD ["python", "agents/patch_agent.py", "--serve", "--port", "8080"]
