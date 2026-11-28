#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Olliver Schinagl <oliver@schinagl.nl>
#
# Check that the installed semonitor is complete: every module can be imported,
# so every dependency is installed, and an installed command runs.
#
# Building an image, or running pip install, succeeds without the extras (they
# are only installed when asked for) and pip check does not look at them, and
# test.sh only needs pyserial. This test fails when a module, such as se2hass,
# se2influx or se2mqtt, lacks a dependency.
#
# Usage: ./test/test-install.sh
#        VENV=.venv ./test/test-install.sh

set -eu

if [ "${DEBUG_TRACE_SH:-}" = 'true' ] || \
   [ "${DEBUG_TRACE_SH:-}" != "${DEBUG_TRACE_SH:+${DEBUG_TRACE_SH#*"$(basename "${0}")"*}}" ]; then
	set -x
fi

check_imports()
{
	"${_bin}python3" - <<-'EOF'
		import importlib
		import pkgutil

		import se

		print("Testing the semonitor from", se.__file__)
		for module in pkgutil.walk_packages(se.__path__, "se."):
		    importlib.import_module(module.name)
	EOF
}

main()
{
	_bin="${VENV:+${VENV}/bin/}"

	check_imports
}

main "${@}"

exit 0
