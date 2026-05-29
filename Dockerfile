FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

EXPOSE 3000

ENV PORT=3000 \
    NODE_ENV=production \
    LLM_PROVIDER=openai \
    LLM_BASE_URL=https://api.openai.com/v1 \
    LLM_MODEL=gpt-4.1-mini

VOLUME ["/app/workspace"]

CMD ["node", "server.js"]