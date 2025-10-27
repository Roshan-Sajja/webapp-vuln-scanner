FROM python:3.11-slim


ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app


RUN apt-get update && \
    apt-get install --no-install-recommends -y build-essential libxml2-dev libxslt1-dev && \
    rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt


COPY . .

# the port Flask app listens on
EXPOSE 5000


ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    DB_PATH=/app/scanner.db


CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "0", "app:app"]
