# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2023 Olliver Schinagl <oliver@schinagl.nl>

# Wait for the system time to be valid. semonitor provides the time to the
# inverter, and the time ends up in the names and the data of its output, so
# it should never run with a bogus time. A device without a battery backed
# clock has none until the time is synchronized, which can take a while.
#
# The time to wait for is set with the SE_START_EPOCH environment variable, as
# a UNIX epoch or as an ISO 8601 date and time (without a time zone it is in
# local time), for example '1735689600', '2025-01-01' or '2025-01-01T12:00Z'.
# Without it the time this program was installed is used, as the time can not
# be before that. SE_START_TIMEOUT is the number of seconds to wait for it, 60
# when not set.

import datetime
import logging
import os
import time

logger = logging.getLogger(__name__)

START_EPOCH = "SE_START_EPOCH"
START_TIMEOUT = "SE_START_TIMEOUT"
DEFAULT_TIMEOUT = 60


class ClockError(Exception):
    """The time is not valid, or the settings to check it are not."""


# convert a UNIX epoch, or an ISO 8601 date and time, to a UNIX epoch
def toEpoch(value):
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return datetime.datetime.fromisoformat(value).timestamp()
    except ValueError:
        raise ClockError(
            f"Invalid '{START_EPOCH}' '{value}', expected a UNIX epoch or an"
            " ISO 8601 date and time."
        ) from None


# the time that has to have passed, when it is not set
def defaultEpoch():
    return os.stat(__file__).st_mtime


def timeout(value):
    if not value:
        return DEFAULT_TIMEOUT
    try:
        return int(value)
    except ValueError:
        raise ClockError(
            f"Invalid '{START_TIMEOUT}' '{value}', expected a number of"
            " seconds."
        ) from None


# wait, a little longer every time, until the time is not before the start
def waitForValidTime(environ=None, now=None, sleep=None):
    environ = os.environ if environ is None else environ
    now = now or time.time
    sleep = sleep or time.sleep

    start = environ.get(START_EPOCH)
    start = toEpoch(start) if start else defaultEpoch()
    seconds = timeout(environ.get(START_TIMEOUT))

    interval = 1
    remaining = seconds
    while now() < start and remaining > 0:
        logger.warning(
            "System time %d older than %d, waiting (override with '%s') ...",
            now(),
            start,
            START_EPOCH,
        )
        sleep(interval)
        remaining -= interval
        interval += 1

    if now() < start:
        raise ClockError(
            f"System time still invalid after {seconds} seconds, giving up."
        )
