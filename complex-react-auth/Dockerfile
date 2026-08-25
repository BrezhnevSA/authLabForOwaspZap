FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY --from=build /app/dist ./dist
ENV PORT=8711
EXPOSE 8711
CMD ["node", "server.js"]
