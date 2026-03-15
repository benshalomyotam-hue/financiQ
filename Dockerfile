FROM python:3.12-slim

WORKDIR /app

# No pip install needed — pure stdlib
COPY server.py app.html ./

# Create data directory for SQLite persistence
RUN mkdir -p /data

ENV PORT=8080
ENV DB_PATH=/data/financiq.db

EXPOSE 8080

CMD ["python3", "server.py"]
