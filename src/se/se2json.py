"""Convert the JSON Lines of semonitor to valid JSON."""

import argparse
import json
import sys

from se.metrics import open_input


def convert(line):
    """
    Return a line of semonitor output as valid JSON.

    semonitor writes NaN for a value that is not valid, and Python reads it
    without complaint, but it is not JSON (RFC 8259) and a strict parser
    refuses it. Every NaN, Infinity and -Infinity becomes null, and nothing else
    changes: not the order of the keys, nor the format of the line.

    A line that is not JSON, or has a number that is too large to write as
    valid JSON, makes it raise ValueError.

    Args:
        line: One line of the output of semonitor.

    Returns:
        The same data as a line of valid JSON, without the newline.
    """
    # The constants are NaN, Infinity and -Infinity, and null is None.
    return json.dumps(
        json.loads(line, parse_constant=lambda _constant: None),
        allow_nan=False,
    )


def main(argv=None):
    """
    Write the JSON read as valid JSON.

    Args:
        argv: The command line arguments to use, or None for those of the
            process.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Read a file containing JSON performance data, one object per "
            "line, and write it as valid JSON. The values that are not valid "
            "JSON, NaN, Infinity and -Infinity, become null."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "infile",
        nargs="?",
        help="file containing performance data in JSON format (default: stdin)",
    )

    args = parser.parse_args(argv)

    with open_input([args.infile] if args.infile else []) as in_file:
        for line_no, line in enumerate(in_file, 1):
            if not line.strip():
                continue
            try:
                converted = convert(line)
            except ValueError as ex:
                sys.exit(f"{parser.prog}: line {line_no}: {ex}")
            sys.stdout.write(converted + "\n")
            # Whoever reads this may be waiting for the next line
            sys.stdout.flush()


if __name__ == "__main__":
    main()
