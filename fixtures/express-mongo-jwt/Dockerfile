FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
ENV JWT_SECRET=supersecret
EXPOSE 4000
CMD ["npm", "run", "dev"]
