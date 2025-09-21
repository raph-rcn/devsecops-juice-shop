FROM alpine/git AS src
WORKDIR /src
RUN git clone --depth=1 https://github.com/juice-shop/juice-shop.git .
FROM node:20-alpine
WORKDIR /app
COPY --from=src /src ./
RUN npm ci --only=production
ENV NODE_ENV=production
EXPOSE 3000
USER node
CMD ["npm","start"]
