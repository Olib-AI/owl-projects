#!/bin/bash
# Prepare StealthFormBot for Apify deployment
# This script bundles the owl-browser SDK with the actor

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTOR_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$ACTOR_DIR")"
SDK_DIR="$PROJECT_ROOT/python-sdk"
BUNDLE_DIR="$ACTOR_DIR/owl_browser_sdk"

echo "=== Preparing StealthFormBot for Apify Deployment ==="
echo "Actor directory: $ACTOR_DIR"
echo "SDK source: $SDK_DIR"
echo "Bundle destination: $BUNDLE_DIR"

# Check if SDK exists
if [ ! -d "$SDK_DIR" ]; then
    echo "ERROR: owl-browser SDK not found at $SDK_DIR"
    exit 1
fi

# Remove old bundle if exists
if [ -d "$BUNDLE_DIR" ]; then
    echo "Removing old SDK bundle..."
    rm -rf "$BUNDLE_DIR"
fi

# Copy SDK to actor directory
echo "Bundling owl-browser SDK..."
cp -r "$SDK_DIR" "$BUNDLE_DIR"

# Remove unnecessary files from bundle
echo "Cleaning up bundle..."
rm -rf "$BUNDLE_DIR/.git" 2>/dev/null || true
rm -rf "$BUNDLE_DIR/.mypy_cache" 2>/dev/null || true
rm -rf "$BUNDLE_DIR/__pycache__" 2>/dev/null || true
rm -rf "$BUNDLE_DIR/examples" 2>/dev/null || true
rm -rf "$BUNDLE_DIR/dist" 2>/dev/null || true
rm -rf "$BUNDLE_DIR/*.egg-info" 2>/dev/null || true
find "$BUNDLE_DIR" -name "*.pyc" -delete 2>/dev/null || true
find "$BUNDLE_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

echo "=== Bundle Ready ==="
echo "SDK bundled at: $BUNDLE_DIR"
echo ""
echo "To deploy to Apify:"
echo "  cd $ACTOR_DIR"
echo "  apify push"
echo ""
echo "Or build Docker image locally:"
echo "  docker build -t stealth-form-bot ."
