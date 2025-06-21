# Multi-stage build for better caching
FROM node:23.3.0-slim as base

WORKDIR /app

# Install system dependencies (this layer rarely changes)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install bun globally
RUN npm install -g bun@1.2.5

# Create symbolic link for python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Dependencies stage - only rebuilds when package files change
FROM base as deps
COPY package.json bun.lockb* package-lock.json* ./
RUN bun install

# Build stage - rebuilds when source code changes
FROM deps as builder
COPY scripts/source-hash.sh ./scripts/
COPY src/ ./src/
COPY tsconfig.json* tsup.config.ts* ./
# Generate source hash to invalidate cache on source changes
RUN ./scripts/source-hash.sh
RUN bun run build

# Runtime stage - final image
FROM deps as runtime
COPY --from=builder /app/dist ./dist
COPY . .

# Expose port for API server
EXPOSE 3001

# Set NODE_ENV to development
ENV NODE_ENV=development

# Use the built version
CMD ["elizaos", "start"]
