# --- stage 1: fetch source
FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .

# --- stage 2: runtime/build
FROM node:22-bookworm-slim AS app
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 make g++ pkg-config libxml2-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=src /src ./

# Rewrite SSH git deps to HTTPS so npm can fetch them in CI
RUN git config --global url."https://github.com/".insteadOf ssh://git@github.com/ \
 && git config --global url."https://github.com/".insteadOf git@github.com:

# Install production deps (prefer lockfile)
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
