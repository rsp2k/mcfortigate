FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY . .
ENV ASTRO_TELEMETRY_DISABLED=1
RUN npm run build

FROM caddy:2-alpine AS prod
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv

FROM node:24-slim AS dev
WORKDIR /app
ENV ASTRO_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "4321"]
