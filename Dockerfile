FROM python:3.9-slim

WORKDIR /app

# Install system dependencies including PostgreSQL client libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create the instance directory for SQLite (needed for development/testing)
RUN mkdir -p instance && chmod 777 instance

# Run as non-root user
RUN useradd -m myuser
USER myuser

# Command to run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
