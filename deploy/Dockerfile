FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    supervisor \
    fonts-liberation \
    fonts-noto-color-emoji \
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libcups2 \
    libxkbcommon0 \
    libgtk-3-0 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV DISPLAY=:99
ENV SCREEN_WIDTH=1280
ENV SCREEN_HEIGHT=800
ENV SCREEN_DEPTH=24

WORKDIR /app

COPY package*.json ./
RUN npm ci
RUN npx playwright install chromium --with-deps

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

RUN mkdir -p /data/browser-profiles /var/log/supervisor

COPY deploy/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 3456 6080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
