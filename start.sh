#!/bin/sh
# App Runner build command: `sh start.sh`
# Fusion runtime: the final image copies only /app from the build stage. Packages
# installed into the global site-packages in the build container are NOT copied.
# Installing into /app/vendor keeps wheels on disk under /app so they ship with the app.
set -e
python3 -m pip install --upgrade pip setuptools wheel 2>/dev/null || true
python3 -m pip install --no-cache-dir -r requirements.txt --target /app/vendor
