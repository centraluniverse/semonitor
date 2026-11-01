"""SolarEdge input data and file management."""

import logging
import sys
import time
from pathlib import Path

import serial

logger = logging.getLogger(__name__)
DATE_PLACEHOLDER = "__date__"
DATETIME_PLACEHOLDER = "__datetime__"


def open_serial(in_file_name, baud_rate):
    """
    Open the serial device in_file_name at baud_rate.

    Args:
        in_file_name: The name of the serial device.
        baud_rate: The baud rate to open it at.

    Returns:
        The open serial port.
    """
    return serial.Serial(in_file_name, baudrate=baud_rate)


def open_in_file(in_file_name):
    """
    Open the data source for reading in binary mode.

    The name "stdin" gives the binary buffer of standard input instead.

    Args:
        in_file_name: The name of the file to open, or "stdin".

    Returns:
        The binary file object to read the data from.
    """
    if in_file_name == "stdin":
        return sys.stdin.buffer
    # Explicitly specify mode rb to keep Windows happy!
    return Path(in_file_name).open("rb")


def close_data(data_file):
    """Close the data source, and log its name."""
    logger.info("closing %s", data_file.name)
    data_file.close()


def open_out_file(file_name, write_mode="wb"):
    """
    Open the output file in write_mode, or return None if no name is given.

    The tokens __date__ and __datetime__ in the name are replaced by the
    current date, and the current date and time. The parent directories of
    the file are created when they are missing. An existing file is never
    overwritten in write mode, the next free name from next_free_file_name()
    is used instead.

    Args:
        file_name: The name of the file, which may be empty or None.
        write_mode: The mode to open the file in.

    Returns:
        The open file, or None if no name is given.
    """
    if file_name:
        file_name = file_name.replace(DATE_PLACEHOLDER, time.strftime("%Y%m%d"))
        file_name = file_name.replace(
            DATETIME_PLACEHOLDER, time.strftime("%Y%m%d%H%M%S")
        )
        path = Path(file_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if write_mode == "wb":
            path = Path(next_free_file_name(file_name))
        return path.open(write_mode)
    return None


def next_free_file_name(file_name):
    """
    Return file_name, or if that file exists, the first free numbered name.

    The counter is put before the extension: out.json becomes out.1.json,
    out.2.json and so on.

    Args:
        file_name: The name of the file wanted.

    Returns:
        The name to use, which is file_name if no file of that name exists.
    """
    path = Path(file_name)
    if not path.is_file():
        return file_name
    count = 1
    while path.with_name(f"{path.stem}.{count}{path.suffix}").exists():
        count += 1
    return str(path.with_name(f"{path.stem}.{count}{path.suffix}"))


def close_out_files(rec_file, out_file):
    """Close the record and output files, logging the name of each closed."""
    if rec_file:
        logger.info("closing %s", rec_file.name)
        rec_file.close()
    if out_file:
        logger.info("closing %s", out_file.name)
        out_file.close()
