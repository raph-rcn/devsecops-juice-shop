# --- stage 1: fetch source
FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .

# --- stage 2: build (needs dev deps + native toolchain)
FROM node:22-bookworm-slim AS build
WORKDIR /app

# toolchain for native modules + git for git-based deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 make g++ pkg-config libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# bring source in and install ALL deps (incl. dev)
COPY --from=src /src ./
RUN npm ci

# build the frontend/bundles
RUN npm run build

# drop dev deps so only prod deps remain
RUN npm prune --omit=dev

# --- stage 3: runtime (small, prod-only)
FROM node:22-bookworm-slim AS app
WORKDIR /app
ENV NODE_ENV=production

# only copy the built tree with pruned node_modules
COPY --from=build /app /app

# (optional) add a healthcheck that doesn't need curl/wget
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD \
  node -e 'require("http").get("http://localhost:3000",r=>process.exit(r.statusCode===200?0:1)).on("error",()=>process.exit(1))'

EXPOSE 3000
CMD ["npm", "start"]
