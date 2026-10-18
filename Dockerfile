FROM node:22-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application source
COPY . .

# Expose port
ENV PORT=3000
EXPOSE 3000

# Start server
CMD ["node", "server.js"]
