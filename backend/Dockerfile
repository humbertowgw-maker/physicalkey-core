# Debian-based, not node:26-alpine: Alpine's git apk build excludes git-http-backend
# entirely (confirmed — it's not a missing package, Alpine's own git build doesn't ship
# it), and the honeypot bait repo (honeypot/bait-repo.js) and server.js's /backup.git
# route both need it to serve real git smart-HTTP. Debian's git package includes it.
FROM node:26-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY auth ./auth
COPY audit ./audit
COPY git ./git
COPY honeypot ./honeypot
COPY lib ./lib
COPY payments ./payments
COPY scripts ./scripts

# Persistent volume mounts here in production (see railway volume config) so the
# SQLite database survives redeploys and restarts.
RUN mkdir -p /app/data

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
