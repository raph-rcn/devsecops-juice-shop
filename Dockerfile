# --- Stage 1: fetch source ---
FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .

# --- Stage 2: runtime image ---
FROM node:20-alpine
WORKDIR /app

# copy everything (so the check can see if a lockfile exists)
COPY --from=src /src ./

# If a lockfile exists, use CI; otherwise fall back to install
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm","start"]
