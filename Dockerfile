# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (build-essential for argon2-cffi)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port Flask runs on
EXPOSE 5000

# Start with Gunicorn for production
# -b 0.0.0.0:$PORT allows Render/Heroku to bind their dynamic port
CMD gunicorn --bind 0.0.0.0:$PORT app:app
