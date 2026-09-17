# Valtros lab target: lab-api
# Stdlib-only Python HTTP server: no pip installs, builds fully offline.
FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 8000
CMD ["python3", "/app/server.py"]
