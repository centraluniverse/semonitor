#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
if [ -n "${DEBUG_TRACE_SH:-}" ] && \
   [ "${DEBUG_TRACE_SH:-}" != "${DEBUG_TRACE_SH#*"$(basename "${0}")"*}" ] || \
   [ "${DEBUG_TRACE_SH:-}" = 'all' ]; then
	set -x
fi

exec '/usr/local/src/solaredge/semonitor.py' "${@}"

exit 0
