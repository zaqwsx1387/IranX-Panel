FROM python:3.11-slim

WORKDIR /app

# Create data directory for SQLite
RUN mkdir -p /data

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY main.py .
COPY start.sh .
RUN chmod +x start.sh

# Railway injects $PORT at runtime
EXPOSE 8000

CMD ["/app/start.sh"]
