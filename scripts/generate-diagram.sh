#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH="/Users/Yousef/.nix-profile/bin:/opt/homebrew/bin:${PATH}"

echo "Generating Lucidchart-style visual architecture diagram..."
"${REPO_ROOT}/.venv/bin/python3" "${SCRIPT_DIR}/generate_architecture_diagram.py"

if [[ -f "${REPO_ROOT}/docs/architecture-overview.png" ]]; then
    echo "✔ Successfully generated docs/architecture-overview.png"
else
    echo "❌ Diagram generation failed"
    exit 1
fi
