"""
Convert a debug log back into a binary data file.

The log must have been created by semonitor.py with the -vvvv option which
dumps the raw data.

Usage:
  python se2hex.py logFile [dataFile]
      logFile     file containing semonitor.py debug output created with the
                  -vvvv option
      dataFile    file to write data to (default: stdout)
"""

import argparse
import binascii
import contextlib
import sys
from pathlib import Path


def main(argv=None):
    """Write the data lines of a debug log to a binary file or stdout."""
    parser = argparse.ArgumentParser(
        description="Convert a semonitor debug log back into a binary file.",
    )
    parser.add_argument(
        "logfile",
        help="file containing semonitor debug output created with -vvvv",
    )
    parser.add_argument(
        "datafile",
        nargs="?",
        help="file to write the data to (default: stdout)",
    )
    args = parser.parse_args(argv)
    with contextlib.ExitStack() as files:
        log_file = files.enter_context(Path(args.logfile).open())
        data_file = (
            sys.stdout.buffer
            if args.datafile is None
            else files.enter_context(Path(args.datafile).open("wb"))
        )

        for line in log_file:
            if line[0:5] == "data:":
                data_file.write(
                    binascii.unhexlify(line[5:].replace(" ", "").strip())
                )


if __name__ == "__main__":
    main()
