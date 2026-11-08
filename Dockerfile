FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
ARG XRAY_VERSION=v1.8.24
RUN curl -L -o /tmp/x.zip https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip \
 && unzip /tmp/x.zip xray geoip.dat geosite.dat -d /usr/local/bin && chmod +x /usr/local/bin/xray && rm /tmp/x.zip
COPY --from=caddy:2.8 /usr/bin/caddy /usr/local/bin/caddy
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.30.6
COPY main.py admin.html Caddyfile start.sh ./
RUN chmod +x start.sh
CMD ["./start.sh"]
