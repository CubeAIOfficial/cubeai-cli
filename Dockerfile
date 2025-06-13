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

# Install bun and nodemon globally
RUN npm install -g bun@1.2.5
RUN npm install -g nodemon

# Create symbolic link for python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Copy only package files first for better cache
COPY package.json bun.lockb* package-lock.json* ./

# Install dependencies (including devDependencies)
RUN bun install

# Install eliza CLI globally (after bun install for better cache)
RUN npm install -g @elizaos/cli

# Copy the rest of the code
COPY . .

# Expose ports for API server (3001) and client (3000)
EXPOSE 3000 3001

# Set NODE_ENV to development for auto-restart
ENV NODE_ENV=development

# Use dev script for development mode
CMD ["bun", "run", "dev"]
