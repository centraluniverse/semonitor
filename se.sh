#!/bin/sh

set -eu

if [ "${DEBUG_TRACE_SH:-}" = 'true' ] || \
   [ "${DEBUG_TRACE_SH:-}" != "${DEBUG_TRACE_SH:+${DEBUG_TRACE_SH#*"$(basename "${0}")"*}}" ]; then
	set -x
fi

if ! command -v python3 > '/dev/null' 2>&1; then
	echo "python3 is required to create the virtualenv" >&2
	exit 1
fi

if [ "${#}" -lt 1 ] || [ "${1}" = '-h' ]; then
	echo "Missing argument. Try with 'semonitor'." >&2
	exit 1
fi

_module="${1}"
shift

VENV="${VENV:-${PWD}/.venv}"
_python="${VENV:+${VENV}/bin/}python3"
export PYTHONPATH="${PWD}/src"
if [ ! -x "${_python}" ]; then
	echo "Virtualenv not found at '${VENV}'. Create it with:" >&2
	echo "  python3 -m venv '${VENV}'"
	echo "  '${_python}' -m pip install --quiet '.[all]'" >&2
	exit 1
fi

exec "${_python}" -m "se.${_module}" "${@}"

exit 0
