# --- stage 1: fetch source
FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .

# --- stage 2: runtime/build
FROM node:20-alpine AS app
WORKDIR /app

# npm needs git for git-based deps
RUN apk add --no-cache git

# bring the code in
COPY --from=src /src ./

# install production deps (use lockfile if present)
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
