#!/bin/bash

# default to patch version bump
VERSION_TYPE="${1:-patch}"
OUT_DIR="${2:-./local-distribution}"

# bump version in package.json
npm version $VERSION_TYPE --no-git-tag-version

# pack the package
npm pack

# get package name and version
PACKAGE_NAME=$(node -p "require('./package.json').name.replace('@', '').replace('/', '-')")
PACKAGE_VERSION=$(node -p "require('./package.json').version")
OUT_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"

# move the tarball to specified directory
if [ "$OUT_DIR" != "./" ]; then
  mkdir -p "$OUT_DIR"
  mv "$OUT_NAME" "$OUT_DIR/"
  echo "Package moved to: $OUT_DIR/$OUT_NAME"
else
  echo "Package created: $OUT_NAME"
fi
