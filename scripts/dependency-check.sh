#!/usr/bin/env sh
set -eu

mkdir -p reports/dependency-check
docker run --rm --platform linux/amd64 \
  --entrypoint /usr/share/dependency-check/bin/dependency-check.sh \
  -v "$(pwd):/src" \
  owasp/dependency-check-action@sha256:9f800737124f89ef8d34a0ad266311bd27230e818be97f910645ddb5e4e9cbf7 \
  --project secure-notes-api --scan /src --format HTML \
  --out /src/reports/dependency-check --failOnCVSS 7 --disableOssIndex \
  --exclude '**/node_modules/**' --exclude '**/docs/**' \
  --exclude '**/reports/**' --exclude '**/tmp/**' --exclude '**/.git/**'
