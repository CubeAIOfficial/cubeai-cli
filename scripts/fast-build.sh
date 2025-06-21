#!/bin/bash

set -e

echo "🔨 Starting fast build for cubeai-cli..."

# Generate source hash to help with cache invalidation
./scripts/source-hash.sh

# Build with target caching - only rebuild what changed
echo "📦 Building Docker image..."
docker build \
  --target runtime \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  -t cubeai-cli:latest \
  .

echo "✅ Fast build completed!"
echo "🚀 You can now restart your containers with: docker compose restart cubeai-cli" 