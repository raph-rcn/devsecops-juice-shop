FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .

FROM node:20-alpine
WORKDIR /app

# copy only the files needed for install first (better cache & guarantees lockfile)
COPY --from=src /src/package.json /src/package-lock.json ./

# npm v10+: use --omit=dev instead of --only=production
RUN npm ci --omit=dev

# now copy the rest of the app
COPY --from=src /src ./

ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm","start"]
