FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt \
    && groupadd --gid 1000 app \
    && useradd --uid 1000 --gid app --no-create-home app \
    && mkdir /app/instance \
    && chown app:app /app/instance

COPY app.py schema.sql ./
COPY templates ./templates
COPY static ./static
COPY scripts ./scripts
COPY tests ./tests

USER app
EXPOSE 8088
CMD ["gunicorn", "--bind", "0.0.0.0:8088", "--workers", "1", "--threads", "4", "--worker-tmp-dir", "/tmp", "app:create_app()"]
