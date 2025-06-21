#!/bin/bash

# Generate a hash of all source files to help Docker detect changes
find src -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" | \
  sort | \
  xargs cat | \
  sha256sum | \
  cut -d' ' -f1 > .source-hash

echo "Source hash generated: $(cat .source-hash)" 