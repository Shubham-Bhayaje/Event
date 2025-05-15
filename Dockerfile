# Use Python 3.9 slim-buster for better compatibility with face-recognition
FROM python:3.9-slim-buster

# Install minimal system dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    libopenblas-dev \
    liblapack-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy only requirements first for better build caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Set environment variables
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0


# Expose the port that Gunicorn will bind to
EXPOSE 5000

# Start the app using Gunicorn with gevent worker and optimized settings
CMD gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --timeout 300 --worker-class gevent wsgi:app