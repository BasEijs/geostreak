FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
ARG APP_VERSION=dev
ARG GIT_SHA=local
ENV APP_VERSION=$APP_VERSION
ENV GIT_SHA=$GIT_SHA
EXPOSE 3000
CMD ["node", "server.js"]
