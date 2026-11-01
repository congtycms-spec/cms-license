FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
COPY public ./public
COPY prisma ./prisma

RUN npm run build

EXPOSE 4000

CMD ["node", "dist/main.js"]

