#!/bin/sh
mkdir -p /data
# سقف نرم حافظه برای Go (Xray و Caddy)؛ با متغیر GOMEMLIMIT در Railway قابل تغییره
export GOMEMLIMIT="${GOMEMLIMIT:-350MiB}"
caddy run --config /app/Caddyfile --adapter caddyfile &
exec uvicorn main:app --host 127.0.0.1 --port 8000 --no-access-log --log-level warning
