FROM python:3.11-slim

WORKDIR /app

# Create data directory for SQLite
RUN mkdir -p /data

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY main.py .

# Railway injects $PORT at runtime — do NOT hardcode 8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
