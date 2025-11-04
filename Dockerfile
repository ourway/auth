FROM python:3.11-slim

LABEL maintainer="Farsheed Ashouri"
LABEL description="Authorization service for humans"

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install system dependencies and Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn uvicorn[standard] \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy the application code
COPY . .

# Install the package in development mode
RUN pip install -e .

# Create a non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

EXPOSE 4000

# Use uvicorn for FastAPI applications
CMD ["uvicorn", "auth.main:app", "--host", "0.0.0.0", "--port", "4000", "--workers", "2"]

