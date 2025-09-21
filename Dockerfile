# ---------- Stage 1: Build and compile ----------
FROM python:3.12-slim AS builder
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential curl gnupg patchelf

# Install Azure CLI and Bicep CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash && az bicep install

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install nuitka

# Copy CLI scripts
COPY 01_detect_finlythub.py ./
COPY 02_deploy_finlythub.py ./
COPY config.py ./

# Compile scripts to standalone binaries
RUN python3 -m nuitka --onefile --static-libpython=no --output-dir=bin 00_setup_finlythub.py
RUN python3 -m nuitka --onefile --static-libpython=no --output-dir=bin 01_detect_finlythub.py
RUN python3 -m nuitka --onefile --static-libpython=no --output-dir=bin 02_deploy_finlythub.py

# ---------- Stage 2: Final runtime image ----------
FROM python:3.12-slim
WORKDIR /app

# Copy compiled binaries only
COPY --from=builder /app/bin/01_detect_finlythub.bin /usr/local/bin/finlyt-detect
COPY --from=builder /app/bin/02_deploy_finlythub.bin /usr/local/bin/finlyt-deploy

# Copy Bicep template
COPY 02_finlythub_deploy.bicep ./

# Copy Azure CLI from builder
COPY --from=builder /usr/bin/az /usr/bin/az
COPY --from=builder /usr/lib/ /usr/lib/
COPY --from=builder /etc/ /etc/

# Default shell
ENTRYPOINT ["/bin/bash"]
