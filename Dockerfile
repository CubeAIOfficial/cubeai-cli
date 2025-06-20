FROM node:23.3.0-slim

WORKDIR /app

# Install system dependencies
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

# Copy only package files first for better cache
COPY package.json bun.lockb* package-lock.json* ./

# Install dependencies (this includes @elizaos/cli as a dependency)
RUN bun install

# Copy the rest of the code
COPY . .

# Expose port for API server
EXPOSE 3001

# Set NODE_ENV to development
ENV NODE_ENV=development

# Use dev script for development mode with bun
CMD ["bun", "run", "dev"]
