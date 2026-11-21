#!/bin/sh
# Prints the published image names for this commit as GitHub step outputs:
#   ghcr.io/<owner>/<repo>[-browser]:<pyproject version>-<12-character commit>
set -eu
version=$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])")
commit=${GITHUB_SHA:-$(git rev-parse HEAD)}
repository=$(printf %s "${GITHUB_REPOSITORY:?}" | tr '[:upper:]' '[:lower:]')
tag="$version-$(printf %s "$commit" | cut -c1-12)"
echo "gateway=ghcr.io/$repository:$tag"
echo "browser=ghcr.io/$repository-browser:$tag"
echo "labels<<EOF_LABELS"
echo "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}"
echo "org.opencontainers.image.revision=$commit"
echo "org.opencontainers.image.version=$version"
echo "EOF_LABELS"
