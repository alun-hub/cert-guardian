FROM docker.io/node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production image
FROM docker.io/nginx:alpine

# Timezone support
RUN apk add --no-cache tzdata
ENV TZ=Europe/Stockholm

COPY --from=builder /app/dist /usr/share/nginx/html

# Nginx config templates (entrypoint selects one at startup)
RUN mkdir -p /etc/nginx/templates
COPY nginx-http.conf /etc/nginx/templates/nginx-http.conf
COPY nginx-https.conf /etc/nginx/templates/nginx-https.conf

# Default config (HTTP-only, overridden by entrypoint if TLS certs present)
COPY nginx-http.conf /etc/nginx/conf.d/default.conf

# Entrypoint script for TLS detection
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
