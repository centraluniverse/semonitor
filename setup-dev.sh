#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Olliver Schinagl <oliver@schinagl.nl>
#
# Create (or refresh) a local virtualenv with pre-commit and install the git
# hook. Nothing is installed outside of ${VENV} (apart from pre-commit's own
# hook-environment cache in ~/.cache/pre-commit).
#
# Usage: ./setup-dev.sh  # first time setup/re-run to update the linters
#        .venv/bin/pre-commit run --all-files

set -eu

if [ "${DEBUG_TRACE_SH:-}" = 'true' ] || \
   [ "${DEBUG_TRACE_SH:-}" != "${DEBUG_TRACE_SH:+${DEBUG_TRACE_SH#*"$(basename "${0}")"*}}" ]; then
	set -x
fi

VENV="${VENV:-.venv}"

cd "$(dirname "${0}")"

if ! command -v python3 > /dev/null 2>&1; then
	echo "python3 is required to create the virtualenv" >&2
	exit 1
fi

python3 -m venv "${VENV}"
"${VENV}/bin/python" -m pip install --quiet --upgrade pip
"${VENV}/bin/python" -m pip install --quiet --upgrade --requirement requirements-dev.txt

"${VENV}/bin/pre-commit" clean
"${VENV}/bin/pre-commit" install --install-hooks

echo "Done. The git hook uses ${VENV}; no need to activate it."
echo "Run all checks with: ${VENV}/bin/pre-commit run --all-files"
