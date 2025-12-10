# Enclave Dockerfile - Based on Amazon Linux 2023
FROM amazonlinux:2023

# Install Python 3.12 and dependencies
RUN dnf install -y python3.12 python3.12-pip && \
    dnf clean all

# Set Python 3.12 as default
RUN alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 && \
    alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.12 1

# Create app directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir boto3>=1.34.0

# Copy application code
COPY enclave_app.py .

# Make the application executable
RUN chmod +x enclave_app.py

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose vsock port (documentation only, vsock doesn't use traditional ports)
EXPOSE 5000

# Run the enclave application
CMD ["python3", "enclave_app.py"]
