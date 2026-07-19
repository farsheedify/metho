#!/usr/bin/env bash
set -euo pipefail

# Export PATH for Go binaries
export PATH="${PATH}:/root/go/bin:/usr/local/go/bin"

# Ensure output directory exists and is writable
if [[ ! -d "/output" ]]; then
    mkdir -p /output
fi
chmod -R 777 /output 2>/dev/null || true

# Execute the recon script with all passed arguments
exec /opt/scripts/recon.sh "$@"
