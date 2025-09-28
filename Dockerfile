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

# bring in only manifest files first for better caching
COPY --from=src /src/package.json /src/package-lock.json* /app/
# install all deps: prefer lockfile, else regular install
RUN if [ -f package-lock.json ]; then npm ci; else npm install --no-audit --no-fund; fi

# now bring the rest of the source and build
COPY --from=src /src /app
RUN npm run build

# prune dev deps to shrink runtime
RUN npm prune --omit=dev

# --- stage 3: runtime
FROM node:22-bookworm-slim AS app
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app /app

# simple healthcheck without curl/wget
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD \
  node -e 'require("http").get("http://localhost:3000",r=>process.exit(r.statusCode===200?0:1)).on("error",()=>process.exit(1))'

EXPOSE 3000
CMD ["npm", "start"]
