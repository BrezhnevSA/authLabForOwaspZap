FROM node:22-alpine
WORKDIR /app
COPY server.js /app/server.js
COPY certs /app/certs
EXPOSE 8712 9712
CMD ["node", "/app/server.js"]
