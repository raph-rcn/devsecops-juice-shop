# --- stage 1: fetch source
FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .

# --- stage 2: runtime/build
FROM node:22-bookworm-slim AS app
WORKDIR /app

# deps for git-based installs + native module builds (libxmljs2)
RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 make g++ pkg-config libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# bring the code in
COPY --from=src /src ./

# install production deps (use lockfile if present)
# (If CI fails due to lockfile mismatch, fallback to install)

RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
