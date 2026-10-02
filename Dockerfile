FROM node:25-bookworm-slim

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src

ENV NODE_ENV=production
CMD ["node", "src/index.js"]
