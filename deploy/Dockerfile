FROM python:3.12-slim
WORKDIR /app
COPY server/ /app/server/
RUN pip install --no-cache-dir /app/server
ENV HMA_CONFIG=/data/config.toml HMA_DB_PATH=/data/arbiter.sqlite3 HMA_HOST=0.0.0.0
VOLUME /data
EXPOSE 8000
CMD ["sh", "-c", "test -f /data/config.toml || hma init; exec hma serve --config /data/config.toml"]
