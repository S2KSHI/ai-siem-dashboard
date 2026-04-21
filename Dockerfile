FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for scapy and networking
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Create necessary directories
RUN mkdir -p .cache .config .keras templates

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app_groq.py

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app_groq.py"]
