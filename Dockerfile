# in sutation you have command run on diff stage 
FROM node:20 AS bass


FROM bass AS development

WORKDIR /app 
COPY package.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm","run", "start-dev"]

FROM bass AS production 

WORKDIR /app 
COPY package.json .
RUN npm install --only=production
COPY . .
EXPOSE 3000
CMD ["npm","start"]