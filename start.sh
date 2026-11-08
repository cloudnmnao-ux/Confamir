#!/bin/sh
mkdir -p /data
caddy run --config /app/Caddyfile --adapter caddyfile &
exec uvicorn main:app --host 127.0.0.1 --port 8000
