# Multi-stage Dockerfile for AI Bug Bounty Scanner v2.0
FROM python:slim-bullseye AS base



# Install security updates
RUN apt-get update && apt-get upgrade -y && apt-get clean



# Create app user for security
RUN useradd --create-home --shell /bin/bash app

# Set work directory
WORKDIR /app

# Copy and install Python dependencies first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install external security tools stage
FROM base AS tools

# Install Go (required for some tools)
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/usr/local/bin

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.zip && \
    unzip -q nuclei_3.1.0_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei_3.1.0_linux_amd64.zip

# Install Amass
RUN wget -q https://github.com/OWASP/Amass/releases/latest/download/amass_linux_amd64.zip && \
    unzip -q amass_linux_amd64.zip && \
    mv amass_linux_amd64/amass /usr/local/bin/ && \
    chmod +x /usr/local/bin/amass && \
    rm -rf amass_linux_amd64*

# Install Sublist3r
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
    pip install --no-cache-dir -r /opt/Sublist3r/requirements.txt

# Install SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# Create wrapper scripts for Python tools
RUN echo '#!/bin/bash\npython3 /opt/Sublist3r/sublist3r.py "$@"' > /usr/local/bin/sublist3r && \
    echo '#!/bin/bash\npython3 /opt/sqlmap/sqlmap.py "$@"' > /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sublist3r /usr/local/bin/sqlmap

# Update Nuclei templates
RUN nuclei -update-templates

# Final application stage  
FROM tools AS final

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p logs exports uploads instance static/reports && \
    chown -R app:app /app

# Set environment variables for tool paths
ENV NUCLEI_PATH=/usr/local/bin/nuclei \
    SUBLIST3R_PATH=/usr/local/bin/sublist3r \
    AMASS_PATH=/usr/local/bin/amass \
    SQLMAP_PATH=/usr/local/bin/sqlmap

# Switch to app user for security
USER app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command - can be overridden in docker-compose
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "eventlet", "--worker-connections", "1000", "--timeout", "120", "--preload", "app:app"]
&& unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

# Install Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r \
    && pip install -r /opt/Sublist3r/requirements.txt

FROM backend-base AS app

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy built frontend from frontend-builder stage
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create necessary directories
RUN mkdir -p /app/instance /app/logs /app/exports

# Set environment variables
ENV FLASK_APP=backend-app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Expose ports
EXPOSE 5000 5555

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Create entrypoint script
RUN echo '#!/bin/bash\n\
    set -e\n\
    \n\
    # Wait for PostgreSQL\n\
    echo "Waiting for PostgreSQL..."\n\
    while ! nc -z postgres 5432; do\n\
    sleep 1\n\
    done\n\
    echo "PostgreSQL is ready!"\n\
    \n\
    # Wait for Redis\n\
    echo "Waiting for Redis..."\n\
    while ! nc -z redis 6379; do\n\
    sleep 1\n\
    done\n\
    echo "Redis is ready!"\n\
    \n\
    # Run database migrations\n\
    echo "Running database migrations..."\n\
    flask db upgrade\n\
    \n\
    # Start the application\n\
    exec "$@"' > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "backend-app:app"]
