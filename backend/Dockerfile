FROM node:26-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY auth ./auth
COPY git ./git
COPY honeypot ./honeypot
COPY access ./access
COPY lib ./lib

# Persistent volume mounts here in production (see railway volume config) so the
# SQLite database survives redeploys and restarts.
RUN mkdir -p /app/data

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
