#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2023 Olliver Schinagl <oliver@schinagl.nl>
#
# A beginning user should be able to docker run image bash (or sh) without
# needing to learn about --entrypoint
# https://github.com/docker-library/official-images#consistency

set -eu

if [ "${DEBUG_TRACE_SH:-}" = 'true' ] || \
   [ "${DEBUG_TRACE_SH:-}" != "${DEBUG_TRACE_SH:+${DEBUG_TRACE_SH#*"$(basename "${0}")"*}}" ]; then
	set -x
fi

# Run command, unless it is an option, directory, device or data file
if [ "${#}" -gt 0 ] && \
   [ "${1#-}" = "${1}" ] && \
   [ ! -d "${1}" ] && \
   [ ! -b "${1}" ] && \
   [ ! -c "${1}" ] && \
   { [ ! -f "${1}" ] || [ -x "${1}" ]; } && \
   command -v "${1}" > '/dev/null' 2>&1; then
	exec "${@}"
fi


bin='/usr/local/src/semonitor/semonitor.py'

se_start_epoch="${SE_START_EPOCH:-}"
se_start_timeout="${SE_START_TIMEOUT:-60}"


e_err()
{
	echo "err: ${*}" >&2
}

wait_for_valid_time()
{
	if [ -n "${se_start_epoch:-}" ]; then
		_start_epoch="$(date -d "${se_start_epoch}" '+%s' 2> '/dev/null' || true)"
		if [ -z "${_start_epoch}" ]; then
			e_err "Invalid 'SE_START_EPOCH' '${se_start_epoch}', expected a date."
			exit 1
		fi
	else
		_start_epoch="$(date -r "${0}" '+%s' 2> '/dev/null' || true)"
		if [ -z "${_start_epoch}" ]; then
			e_err "Unable to determine timestamp of '${0}', set 'SE_START_EPOCH'."
			exit 1
		fi
	fi

	_interval='1'
	_timeout="${se_start_timeout}"
	while
		_now="$(date '+%s')"
		[ "${_now}" -lt "${_start_epoch}" ] && \
		[ "${_timeout}" -gt 0 ]
	do
		echo "System time ${_now} older than ${_start_epoch}, waiting (override with 'SE_START_EPOCH') ..."
		sleep "${_interval}"
		_timeout="$((_timeout - _interval))"
		_interval="$((_interval + 1))"
	done

	if [ "${_now}" -lt "${_start_epoch}" ]; then
		e_err "System time still invalid after ${se_start_timeout} seconds, giving up."
		exit 1
	fi
}

wait_for_valid_time
exec "${bin}" "${@}"

exit 0
