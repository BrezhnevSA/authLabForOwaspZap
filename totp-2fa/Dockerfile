FROM node:22-alpine
WORKDIR /app
COPY server.js totp.js ./
ENV PORT=3000
EXPOSE 3000
USER node
CMD ["node", "server.js"]
