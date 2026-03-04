#!/bin/bash
# Build script for Linux
# Creates a standalone CZar executable for Linux

set -e

echo "=== Building CZar for Linux ==="
echo "Installing build dependencies..."
pip install -r requirements-dev.txt

echo "Running tests..."
pytest tests/ -v || true

echo "Building executable..."
pyinstaller --onefile --name CZar startCzar.py

echo "Creating distribution archive..."
cd dist
tar -czf CZar-linux-x86_64.tar.gz CZar
cd ..

echo "Build complete!"
echo "Output: dist/CZar-linux-x86_64.tar.gz"
ls -lh dist/CZar-linux-x86_64.tar.gz
