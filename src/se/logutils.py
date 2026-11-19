"""
SolarEdge logging and debugging.

Adds the custom DATA and RAW log levels, a filter that collapses repeated
records, and helpers to dump messages and state variables to the log.
"""

import logging
import sys
import threading
import time
import traceback

LOG_LEVEL_DATA = 9
LOG_LEVEL_RAW = 8

logging.addLevelName(LOG_LEVEL_DATA, "DATA")
logging.addLevelName(LOG_LEVEL_RAW, "RAW")


def _data_log(self, msg, *args, **kwargs):
    if self.isEnabledFor(LOG_LEVEL_DATA):
        self._log(LOG_LEVEL_DATA, msg, args, **kwargs)


def _raw_log(self, msg, *args, **kwargs):
    if self.isEnabledFor(LOG_LEVEL_RAW):
        self._log(LOG_LEVEL_RAW, msg, args, **kwargs)


# log an incoming or outgoing data message
# call internal _log() method to ensure caller information is properly reported
def _message_log(self, direction, seq, msg, end_point=""):
    if not self.isEnabledFor(logging.DEBUG):
        return
    self._log(
        logging.DEBUG,
        "%s %s message: %s length: %s",
        (end_point, direction, seq, len(msg)),
    )
    if self.isEnabledFor(LOG_LEVEL_RAW):
        for line in format_data(msg):
            self._log(LOG_LEVEL_RAW, line, ())


def format_data(data):
    """Yield a hex dump of data, with 16 bytes on each line."""
    line_width = 16
    for i in range(0, len(data), line_width):
        yield "data:       " + " ".join(
            f"{x:02x}" for x in data[i : i + line_width]
        )


logging.Logger.data = _data_log
logging.Logger.raw = _raw_log
logging.Logger.message = _message_log


class ConsecutiveDuplicateFilter(logging.Filter):
    """
    Drop a log record that repeats the one before it.

    Only an uninterrupted run of the same record, from the same logger and at
    the same level, is collapsed. The same record that comes back after
    another one is logged again. The record that ends a run is prefixed with
    the number of records that were dropped.

    The DATA and RAW levels are never collapsed, because the lines of a hex
    dump are often the same.

    Add it to a handler, not to a logger: a logger only filters its own
    records, and the handler sees just the records that its level lets by,
    which are the ones that are shown.
    """

    def __init__(self, min_level=logging.DEBUG):
        """
        Initialize the filter.

        Args:
            min_level: The lowest level of the records that are collapsed.
        """
        super().__init__()
        self.min_level = min_level
        self._last = None
        self._repeats = 0
        self._lock = threading.Lock()  # handlers filter without their lock

    def filter(self, record):
        """Return whether the record is logged."""
        key = (record.name, record.levelno, record.getMessage())
        with self._lock:
            if record.levelno >= self.min_level and key == self._last:
                self._repeats += 1
                return False
            if self._repeats:
                record.msg = (
                    f"[Previous message repeated {self._repeats}x] {record.msg}"
                )
                self._repeats = 0
            self._last = key
            return True


def set_state(state, item, value):
    """Store value under item in state, with the current time."""
    state[item] = [time.time(), value]


def dump_state(state):
    """
    Log the state variables, and the stack traces of all threads.

    Args:
        state: A dict of state variables, as set by set_state.
    """
    logger = logging.getLogger(__name__)
    logger.info("state:")
    for item in state:
        logger.info(
            "      %s %s: %s",
            time.strftime("%H:%M:%S", time.localtime(state[item][0])),
            item,
            state[item][1],
        )
    # The only way to get the frames of the other threads, it is in the docs
    for thread_id, stack in sys._current_frames().items():  # noqa: SLF001
        logger.info("ThreadID: %s", thread_id)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            logger.info(
                '      File: "%s", line %d, in %s', filename, lineno, name
            )
            if line:
                logger.info("            %s", line)
