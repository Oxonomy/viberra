FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# deps
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# app
COPY pyproject.toml /app/
COPY src/ /app/src/

EXPOSE 8080
ENV PYTHONPATH=/app:/app/src
CMD /bin/sh -c "uvicorn src.main:app --host 0.0.0.0 --port 8080"
